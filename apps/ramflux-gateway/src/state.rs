use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as AsyncMutex;

use crate::session::write_gateway_frame;

#[derive(Clone)]
pub(crate) struct RouterMeshClient {
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) tls: ramflux_transport::MeshTlsConfig,
    pub(crate) client: ramflux_transport::MeshHttpClient,
}

#[derive(Clone)]
pub(crate) struct NotifyHttpClient {
    pub(crate) endpoint: String,
    pub(crate) signer: ramflux_node_core::NodeServiceSigningKey,
}

#[derive(Clone)]
pub(crate) struct GatewayQuicContext {
    pub(crate) router: RouterMeshClient,
    pub(crate) notify: NotifyHttpClient,
    pub(crate) state: Arc<Mutex<ramflux_node_core::GatewayState>>,
    pub(crate) store: Arc<ramflux_node_core::GatewayRedbStore>,
    pub(crate) hub: Arc<GatewaySessionHub>,
    pub(crate) remote_addr: SocketAddr,
}

pub(crate) struct GatewaySessionRuntime {
    pub(crate) session_id: String,
    pub(crate) resume_token: String,
    pub(crate) target_delivery_id: String,
}

pub(crate) type GatewaySendHandle =
    Arc<AsyncMutex<Box<dyn ramflux_transport::GatewaySessionFrameSink + Send>>>;

#[derive(Clone)]
pub(crate) struct GatewayHubEntry {
    session_id: String,
    sender: GatewaySendHandle,
}

#[derive(Default)]
pub(crate) struct GatewaySessionHub {
    senders_by_target: AsyncMutex<BTreeMap<String, GatewayHubEntry>>,
}

impl GatewaySessionHub {
    pub(crate) async fn register(
        &self,
        target_delivery_id: String,
        session_id: String,
        sender: GatewaySendHandle,
    ) {
        self.senders_by_target
            .lock()
            .await
            .insert(target_delivery_id, GatewayHubEntry { session_id, sender });
    }

    pub(crate) async fn unregister(&self, target_delivery_id: &str, session_id: &str) {
        let mut senders = self.senders_by_target.lock().await;
        if senders.get(target_delivery_id).is_some_and(|entry| entry.session_id == session_id) {
            senders.remove(target_delivery_id);
        }
    }

    pub(crate) async fn send_to(
        &self,
        target_delivery_id: &str,
        frame: &ramflux_node_core::GatewayServerFrame,
    ) -> anyhow::Result<bool> {
        let sender = self
            .senders_by_target
            .lock()
            .await
            .get(target_delivery_id)
            .map(|entry| Arc::clone(&entry.sender));
        if let Some(sender) = sender {
            let mut sender = sender.lock().await;
            write_gateway_frame(&mut **sender, frame).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
