// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

import Foundation

/// Observes the data-root lock from a fresh file descriptor.
///
/// The core takes an exclusive `flock` on `<data root>/daemon.lock`. `flock` locks belong to
/// the open file description, so a second descriptor in the same process conflicts with the
/// core's descriptor exactly as another process would. The probe never keeps the lock.
enum LockProbe {
    enum State: String {
        /// A fresh descriptor took the exclusive lock: nobody holds it.
        case unlocked
        /// The lock is held by another open file description.
        case held
        /// The lock file does not exist (the core never started here).
        case missing
    }

    static func lockFile(in dataRoot: URL) -> URL {
        dataRoot.appendingPathComponent("daemon.lock")
    }

    static func state(dataRoot: URL) throws -> State {
        let path = lockFile(in: dataRoot).path
        let descriptor = open(path, O_RDWR | O_CLOEXEC)
        if descriptor < 0 {
            if errno == ENOENT { return .missing }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { close(descriptor) }
        if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
            _ = flock(descriptor, LOCK_UN)
            return .unlocked
        }
        if errno == EWOULDBLOCK { return .held }
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }

    /// Write-ahead-log files that still hold data. At suspension there must be none: the
    /// stores were checkpointed and closed.
    static func nonEmptyWriteAheadLogs(dataRoot: URL) -> [String] {
        guard
            let files = FileManager.default.enumerator(
                at: dataRoot, includingPropertiesForKeys: [.fileSizeKey])
        else { return [] }
        var found: [String] = []
        for case let url as URL in files where url.lastPathComponent.hasSuffix("-wal") {
            let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
            if size > 0 { found.append(url.lastPathComponent) }
        }
        return found.sorted()
    }
}
