// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::thread;

use crate::serve::GatewayListenerContext;
use crate::session::handle_gateway_session_transport;
use crate::{GatewayQuicContext, dispatch_quic_json_request};

const GATEWAY_COMPIO_WRITE_CHANNEL_CAPACITY: usize = 1024;
const GATEWAY_COMPIO_READ_CHANNEL_CAPACITY: usize = 1024;

enum CompioGatewayWriteCommand {
    Frame(Vec<u8>),
    Finish,
}

struct CompioGatewayChannelSink {
    sender: tokio::sync::mpsc::Sender<CompioGatewayWriteCommand>,
}

struct CompioGatewayChannelSource {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl ramflux_transport::GatewaySessionFrameSink for CompioGatewayChannelSink {
    fn send_frame<'a>(
        &'a mut self,
        frame: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), ramflux_transport::TransportError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.sender.send(CompioGatewayWriteCommand::Frame(frame.to_vec())).await.map_err(
                |_error| {
                    ramflux_transport::TransportError::Quic(
                        "compio gateway writer channel closed".to_owned(),
                    )
                },
            )
        })
    }

    fn finish(&mut self) -> Result<(), ramflux_transport::TransportError> {
        self.sender
            .try_send(CompioGatewayWriteCommand::Finish)
            .map_err(|error| ramflux_transport::TransportError::Quic(error.to_string()))
    }
}

impl ramflux_transport::GatewaySessionFrameSource for CompioGatewayChannelSource {
    fn recv_frame(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ramflux_transport::TransportError>> + Send + '_>>
    {
        Box::pin(async move {
            self.receiver.recv().await.ok_or_else(|| {
                ramflux_transport::TransportError::Quic(
                    "compio gateway reader channel closed".to_owned(),
                )
            })
        })
    }
}

pub(crate) fn serve_gateway_compio_quic(
    addr: SocketAddr,
    tls: ramflux_transport::MeshTlsConfig,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    thread::Builder::new().name("ramflux-gateway-compio-quic".to_owned()).spawn(move || {
        if let Err(error) = run_gateway_compio_quic(addr, tls, context) {
            tracing::error!(%error, "gateway compio QUIC listener stopped");
        }
    })?;
    Ok(())
}

fn run_gateway_compio_quic(
    addr: SocketAddr,
    tls: ramflux_transport::MeshTlsConfig,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    let runtime = compio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let server =
            ramflux_transport::CompioGatewayQuicServer::bind(&addr.to_string(), &tls).await?;
        let local_addr = server.local_addr()?;
        tracing::info!(addr = %local_addr, "gateway compio QUIC session surface listening");
        loop {
            let connection = match server.accept_connection().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "gateway compio QUIC handshake rejected");
                    continue;
                }
            };
            let context = context.clone();
            compio::runtime::spawn(async move {
                if let Err(error) = handle_gateway_compio_quic_connection(connection, context).await
                {
                    tracing::warn!(%error, "gateway compio QUIC connection failed");
                }
            })
            .detach();
        }
    })
}

async fn handle_gateway_compio_quic_connection(
    connection: ramflux_transport::CompioGatewayQuicConnection,
    context: GatewayListenerContext,
) -> anyhow::Result<()> {
    let remote_addr = connection.remote_address();
    loop {
        let stream = match connection.accept_bidi().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(%error, %remote_addr, "gateway compio QUIC connection stream loop ended");
                return Ok(());
            }
        };
        let context = context.clone();
        compio::runtime::spawn(async move {
            if let Err(error) =
                handle_gateway_compio_quic_stream(stream, context, remote_addr).await
            {
                tracing::warn!(%error, %remote_addr, "gateway compio QUIC stream failed");
            }
        })
        .detach();
    }
}

async fn handle_gateway_compio_quic_stream(
    stream: ramflux_transport::CompioGatewayBidiStream,
    context: GatewayListenerContext,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = stream.split();
    let first_raw = recv.read_frame().await?;
    let first_frame: serde_json::Value = serde_json::from_slice(&first_raw)?;
    if first_frame.get("frame_type").is_some() {
        let frame: ramflux_node_core::GatewayClientFrame = serde_json::from_value(first_frame)?;
        let (write_sender, write_receiver) =
            tokio::sync::mpsc::channel(GATEWAY_COMPIO_WRITE_CHANNEL_CAPACITY);
        let (read_sender, read_receiver) =
            tokio::sync::mpsc::channel(GATEWAY_COMPIO_READ_CHANNEL_CAPACITY);
        compio::runtime::spawn(async move {
            if let Err(error) = run_gateway_compio_writer(send, write_receiver).await {
                tracing::warn!(%error, "gateway compio writer failed");
            }
        })
        .detach();
        spawn_gateway_session_worker(write_sender, read_receiver, context, remote_addr, frame)?;
        while let Ok(frame) = recv.read_frame().await {
            if read_sender.send(frame).await.is_err() {
                break;
            }
        }
        return Ok(());
    }

    let request: ramflux_transport::GatewayQuicRequest = serde_json::from_value(first_frame)?;
    let response = dispatch_gateway_request_blocking(context.router.clone(), request).await?;
    send.write_json_message(&response).await?;
    send.finish()?;
    Ok(())
}

async fn run_gateway_compio_writer(
    mut send: ramflux_transport::CompioGatewaySendStream,
    mut receiver: tokio::sync::mpsc::Receiver<CompioGatewayWriteCommand>,
) -> anyhow::Result<()> {
    while let Some(command) = receiver.recv().await {
        match command {
            CompioGatewayWriteCommand::Frame(frame) => send.write_frame(&frame).await?,
            CompioGatewayWriteCommand::Finish => {
                send.finish()?;
                return Ok(());
            }
        }
    }
    Ok(())
}

fn spawn_gateway_session_worker(
    write_sender: tokio::sync::mpsc::Sender<CompioGatewayWriteCommand>,
    read_receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    context: GatewayListenerContext,
    remote_addr: SocketAddr,
    first_frame: ramflux_node_core::GatewayClientFrame,
) -> anyhow::Result<()> {
    thread::Builder::new().name("ramflux-gateway-compio-session".to_owned()).spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(%error, "gateway compio session worker runtime failed");
                return;
            }
        };
        let context = GatewayQuicContext {
            router: context.router,
            notify: context.notify,
            state: context.state,
            store: context.store,
            hub: context.hub,
            remote_addr,
        };
        let sink = CompioGatewayChannelSink { sender: write_sender };
        let source = CompioGatewayChannelSource { receiver: read_receiver };
        if let Err(error) = runtime.block_on(handle_gateway_session_transport(
            Box::new(sink),
            Box::new(source),
            context,
            first_frame,
        )) {
            tracing::warn!(%error, "gateway compio session worker failed");
        }
    })?;
    Ok(())
}

async fn dispatch_gateway_request_blocking(
    router: crate::RouterMeshClient,
    request: ramflux_transport::GatewayQuicRequest,
) -> anyhow::Result<ramflux_transport::GatewayQuicResponse> {
    let (sender, receiver) =
        tokio::sync::oneshot::channel::<anyhow::Result<ramflux_transport::GatewayQuicResponse>>();
    thread::Builder::new().name("ramflux-gateway-compio-request".to_owned()).spawn(move || {
        let _result = sender.send(dispatch_quic_json_request(&router, request));
    })?;
    receiver.await?
}
