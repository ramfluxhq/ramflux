// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SQLite ownership boundary. Connections and statements never leave their DB thread.

use rusqlite::types::{FromSql, ToSql, ToSqlOutput, Value, ValueRef};
use rusqlite::{Error, OpenFlags, Result};
use std::path::Path;
use std::sync::mpsc::{self, SyncSender};
use std::thread::JoinHandle;

type Job = Box<dyn FnOnce(&mut rusqlite::Connection) + Send>;

#[derive(Clone)]
pub(crate) struct Connection {
    inner: std::sync::Arc<Worker>,
}
struct Worker {
    sender: Option<SyncSender<Job>>,
    worker: Option<JoinHandle<()>>,
}

impl Connection {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_flags(path, OpenFlags::default())
    }

    pub(crate) fn open_with_flags(path: impl AsRef<Path>, flags: OpenFlags) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (sender, receiver) = mpsc::sync_channel::<Job>(64);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("ramflux-db".to_owned())
            .spawn(move || {
                let opened = rusqlite::Connection::open_with_flags(path, flags).and_then(|db| {
                    db.busy_timeout(std::time::Duration::from_secs(5))?;
                    Ok(db)
                });
                match opened {
                    Ok(mut db) => {
                        if ready_tx.send(Ok(())).is_ok() {
                            while let Ok(job) = receiver.recv() {
                                job(&mut db);
                            }
                        }
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                    }
                }
            })
            .map_err(|_| Error::InvalidQuery)?;
        ready_rx.recv().map_err(|_| Error::InvalidQuery)??;
        Ok(Self {
            inner: std::sync::Arc::new(Worker { sender: Some(sender), worker: Some(worker) }),
        })
    }

    fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut rusqlite::Connection) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.inner
            .sender
            .as_ref()
            .ok_or(Error::InvalidQuery)?
            .send(Box::new(move |db| {
                let _ = sender.send(f(db));
            }))
            .map_err(|_| Error::InvalidQuery)?;
        receiver.recv().map_err(|_| Error::InvalidQuery)?
    }

    pub(crate) fn execute_batch(&self, sql: &str) -> Result<()> {
        let sql = sql.to_owned();
        self.call(move |db| db.execute_batch(&sql))
    }

    pub(crate) fn execute(&self, sql: &str, params: impl Parameters) -> Result<usize> {
        let sql = sql.to_owned();
        let values = params.values()?;
        self.call(move |db| db.execute(&sql, rusqlite::params_from_iter(values)))
    }

    fn rows(&self, sql: &str, params: impl Parameters) -> Result<Vec<Row>> {
        let sql = sql.to_owned();
        let values = params.values()?;
        self.call(move |db| {
            let mut statement = db.prepare(&sql)?;
            let columns = statement.column_count();
            let mut rows = statement.query(rusqlite::params_from_iter(values))?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                let values =
                    (0..columns).map(|index| row.get(index)).collect::<Result<Vec<Value>>>()?;
                result.push(Row(values));
            }
            Ok(result)
        })
    }

    pub(crate) fn query_row<T>(
        &self,
        sql: &str,
        params: impl Parameters,
        f: impl FnOnce(&Row) -> Result<T>,
    ) -> Result<T> {
        let rows = self.rows(sql, params)?;
        f(rows.first().ok_or(Error::QueryReturnedNoRows)?)
    }

    pub(crate) fn prepare(&self, sql: &str) -> Result<Statement<'_>> {
        let owned = sql.to_owned();
        self.call(move |db| {
            db.prepare(&owned)?;
            Ok(())
        })?;
        Ok(Statement { connection: self, sql: sql.to_owned() })
    }

    pub(crate) fn is_autocommit(&self) -> Result<bool> {
        self.call(|db| Ok(db.is_autocommit()))
    }

    pub(crate) fn unchecked_transaction(&self) -> Result<Transaction<'_>> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nested = !self.call(|db| Ok(db.is_autocommit()))?;
        let savepoint = nested.then(|| {
            format!("runtime_nested_{}", NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        });
        if let Some(name) = &savepoint {
            self.execute_batch(&format!("SAVEPOINT {name}"))?;
        } else {
            self.execute_batch("BEGIN DEFERRED")?;
        }
        Ok(Transaction { connection: self, committed: false, savepoint })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(crate) trait Parameters {
    fn values(self) -> Result<Vec<Value>>;
}

fn owned(value: &dyn ToSql) -> Result<Value> {
    match value.to_sql()? {
        ToSqlOutput::Borrowed(value) => Ok(value.into()),
        ToSqlOutput::Owned(value) => Ok(value),
        _ => Err(Error::InvalidQuery),
    }
}

impl<const N: usize> Parameters for [&dyn ToSql; N] {
    fn values(self) -> Result<Vec<Value>> {
        self.into_iter().map(owned).collect()
    }
}

impl Parameters for &[&dyn ToSql] {
    fn values(self) -> Result<Vec<Value>> {
        self.iter().map(|value| owned(*value)).collect()
    }
}

pub(crate) struct Row(Vec<Value>);

impl Row {
    pub(crate) fn get<I: TryInto<usize>, T: FromSql>(&self, index: I) -> Result<T> {
        let index = index.try_into().map_err(|_| Error::InvalidQuery)?;
        let value = self.0.get(index).ok_or(Error::InvalidColumnIndex(index))?;
        T::column_result(ValueRef::from(value)).map_err(|error| {
            Error::FromSqlConversionFailure(index, value.data_type(), Box::new(error))
        })
    }
}

pub(crate) struct Statement<'a> {
    connection: &'a Connection,
    sql: String,
}

impl Statement<'_> {
    pub(crate) fn query_row<T>(
        &mut self,
        params: impl Parameters,
        f: impl FnOnce(&Row) -> Result<T>,
    ) -> Result<T> {
        self.connection.query_row(&self.sql, params, f)
    }

    pub(crate) fn query_map<T>(
        &mut self,
        params: impl Parameters,
        mut f: impl FnMut(&Row) -> Result<T>,
    ) -> Result<std::vec::IntoIter<Result<T>>> {
        Ok(self
            .connection
            .rows(&self.sql, params)?
            .iter()
            .map(&mut f)
            .collect::<Vec<_>>()
            .into_iter())
    }

    pub(crate) fn query(&mut self, params: impl Parameters) -> Result<Rows> {
        Ok(Rows { rows: self.connection.rows(&self.sql, params)?.into_iter(), current: None })
    }
}

pub(crate) struct Rows {
    rows: std::vec::IntoIter<Row>,
    current: Option<Row>,
}
impl Rows {
    pub(crate) fn next(&mut self) -> Option<&Row> {
        self.current = self.rows.next();
        self.current.as_ref()
    }
}

pub(crate) struct Transaction<'a> {
    connection: &'a Connection,
    committed: bool,
    savepoint: Option<String>,
}
impl Transaction<'_> {
    pub(crate) fn commit(mut self) -> Result<()> {
        if let Some(name) = &self.savepoint {
            self.connection.execute_batch(&format!("RELEASE SAVEPOINT {name}"))?;
        } else {
            self.connection.execute_batch("COMMIT")?;
        }
        self.committed = true;
        Ok(())
    }
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(name) = &self.savepoint {
                let _ = self.connection.execute_batch(&format!(
                    "ROLLBACK TO SAVEPOINT {name}; RELEASE SAVEPOINT {name}"
                ));
            } else {
                let _ = self.connection.execute_batch("ROLLBACK");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Connection;
    #[test]
    fn sqlite_connection_and_statements_stay_on_one_dedicated_thread() -> rusqlite::Result<()> {
        let caller = std::thread::current().id();
        let db = Connection::open(":memory:")?;
        let owner = db.call(|db| {
            db.execute_batch("CREATE TABLE owner(value INTEGER); INSERT INTO owner VALUES(1)")?;
            Ok(std::thread::current().id())
        })?;
        let second = db.call(|db| {
            let value: i64 = db.query_row("SELECT value FROM owner", [], |row| row.get(0))?;
            assert_eq!(value, 1);
            Ok(std::thread::current().id())
        })?;
        assert_ne!(owner, caller);
        assert_eq!(owner, second);
        Ok(())
    }
    #[test]
    fn nested_state_batches_rollback_with_the_outer_message_projection() -> rusqlite::Result<()> {
        let db = Connection::open(":memory:")?;
        db.execute_batch("CREATE TABLE state(value INTEGER)")?;
        {
            let _outer = db.unchecked_transaction()?;
            db.execute_batch("INSERT INTO state VALUES(1)")?;
            let inner = db.unchecked_transaction()?;
            db.execute_batch("INSERT INTO state VALUES(2)")?;
            inner.commit()?;
        }
        let count: i64 = db.query_row("SELECT count(*) FROM state", [], |row| row.get(0))?;
        assert_eq!(count, 0);
        Ok(())
    }
}
