// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Frozen capability binding and asynchronous durable-session adapters.
mod validation;
use crate::{GatewayQuicContext,GatewaySessionRuntime,GatewaySendHandle,RouterMeshClient};
use ramflux_node_core::{SessionPushClientFrame as Client,SessionPushNackReason as Reason};
use serde_json::{Value,json};
use std::sync::{Arc,atomic::{AtomicBool,Ordering}};
use std::time::Duration;
const REQUEST_TIMEOUT:Duration=Duration::from_secs(10);
#[derive(Default)]
pub(crate) struct Readiness {
    started:AtomicBool,
    ready:AtomicBool,
}
impl Readiness {
    pub(crate) fn start(self:&Arc<Self>,router:&RouterMeshClient) {
        if self.started.swap(true,Ordering::AcqRel) {return;}
        let weak=Arc::downgrade(self);let router=router.clone();
        tokio::spawn(async move {
            loop {
                if weak.strong_count()==0 {return;}
                let result=tokio::time::timeout(Duration::from_secs(2),crate::router_get_json_async::<Value>(&router,"/mvp1/session-push-capabilities")).await;
                let ready=result.ok().and_then(Result::ok).is_some_and(|value|capability_reply(&value));
                let Some(state)=weak.upgrade() else {return;};
                state.ready.store(ready,Ordering::Release);drop(state);
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }
    pub(crate) fn supports(&self)->bool {self.ready.load(Ordering::Acquire)}
    #[cfg(test)]
    fn set(&self,ready:bool) {self.ready.store(ready,Ordering::Release);}
}
fn capability_reply(value:&Value)->bool {
    value.get("capabilities").and_then(Value::as_array).is_some_and(|caps|caps.len()<=64 && caps.iter().all(|v|v.as_str().is_some_and(|s|!s.is_empty() && s.len()<=256)) && caps.iter().any(|v|v==ramflux_protocol::GATEWAY_SESSION_PUSH_CAPABILITY))
}
#[derive(Debug)]
pub(crate) struct Retired;
impl std::fmt::Display for Retired {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("capable session router binding retired")}}
impl std::error::Error for Retired {}
pub(crate) fn recognizes(bytes:&[u8],capable:bool)->bool {
    #[derive(serde::Deserialize)]
    struct Tag {frame_type:String,#[serde(default)]incarnation_id:Option<String>}
    serde_json::from_slice::<Tag>(bytes).is_ok_and(|tag|matches!(tag.frame_type.as_str(),"fetch_entry"|"ack_batch") || ((capable || tag.incarnation_id.is_some()) && matches!(tag.frame_type.as_str(),"resume"|"ack"|"nack")))
}
pub(crate) async fn write(send:&GatewaySendHandle,value:&impl serde::Serialize)->anyhow::Result<()> {
    let bytes=serde_json::to_vec(value)?;
    anyhow::ensure!(bytes.len()<=ramflux_node_core::ENTRY_FRAME_BYTE_CAP,"capable frame too large");
    tokio::time::timeout(Duration::from_secs(15),async {
        let mut sink=send.lock().await;
        ramflux_transport::GatewaySessionFrameSink::send_frame(&mut **sink,&bytes).await.map_err(crate::session_response::ClientWriteFailure)
    }).await.map_err(|_|Retired)??;
    Ok(())
}
async fn nack(send:&GatewaySendHandle,id:&str,reason:Reason)->anyhow::Result<()> {
    write(send,&ramflux_node_core::SessionPushServerFrame::Nack {reason,incarnation_id:Some(id.into())}).await
}
async fn post(router:&RouterMeshClient,path:&str,body:&Value)->anyhow::Result<Value> {
    tokio::time::timeout(REQUEST_TIMEOUT,crate::router_post_json_async(router,path,body)).await.map_err(|_|Retired)?.map_err(|_|Retired.into())
}
async fn get(router:&RouterMeshClient,path:&str)->anyhow::Result<Value> {
    tokio::time::timeout(REQUEST_TIMEOUT,crate::router_get_json_async(router,path)).await.map_err(|_|Retired)?.map_err(|_|Retired.into())
}
fn check_epoch(value:&Value,id:&str)->anyhow::Result<()> {
    if value.get("incarnation_id").and_then(Value::as_str)!=Some(id) {return Err(Retired.into());}
    Ok(())
}
async fn issued(context:&GatewayQuicContext,runtime:&GatewaySessionRuntime,id:&str)->anyhow::Result<u64> {
    let value=post(&context.router,"/mvp0/issued-seqs",&json!({"targets":[runtime.target_delivery_id]})).await?;
    let rows=value["issued"].as_array().ok_or(Retired)?;
    anyhow::ensure!(rows.len()==1 && rows[0]["target_delivery_id"]==runtime.target_delivery_id,Retired);
    check_epoch(&rows[0],id)?;
    rows[0]["inbox_seq"].as_u64().ok_or_else(||Retired.into())
}
async fn router_refusal(send:&GatewaySendHandle,id:&str,value:&Value)->anyhow::Result<bool> {
    let Some(reason)=value.get("reason") else {return Ok(false);};
    if value.get("incarnation_id").is_some_and(|v|v!=id) {return Err(Retired.into());}
    let reason=serde_json::from_value::<Reason>(reason.clone()).map_err(|_|Retired)?;
    nack(send,id,reason).await?;Ok(true)
}
fn frame_id(frame:&Client)->&str {
    match frame {Client::Resume {incarnation_id,..}|Client::FetchEntry {incarnation_id,..}|Client::AckBatch {incarnation_id,..}|Client::Ack {incarnation_id,..}|Client::Nack {incarnation_id,..}=>incarnation_id}
}
pub(crate) async fn handle(send:&GatewaySendHandle,context:&GatewayQuicContext,runtime:&GatewaySessionRuntime,bytes:&[u8])->anyhow::Result<()> {
    let Some(id)=runtime.session_push.as_deref() else {
        return crate::session::write_gateway_handle(send,&ramflux_node_core::GatewayServerFrame::Nack {reason:"gateway_request_invalid".into()}).await;
    };
    if bytes.len()>ramflux_node_core::ENTRY_FRAME_BYTE_CAP {return nack(send,id,Reason::PayloadTooLarge).await;}
    let Ok(frame)=ramflux_protocol::parse_i_json::<Client>(bytes) else {return nack(send,id,Reason::GatewayRequestInvalid).await;};
    if !ramflux_node_core::valid_inbox_incarnation(frame_id(&frame)) || frame_id(&frame)!=id {return nack(send,id,Reason::IncarnationMismatch).await;}
    match frame {
        Client::Resume {resume,..}=>{
            if resume.target_delivery_id!=runtime.target_delivery_id || resume.resume_token!=runtime.resume_token {return nack(send,id,Reason::InvalidResumeToken).await;}
            if resume.limit==0 {return nack(send,id,Reason::InvalidLimit).await;}
            let mut response=get(&context.router,&format!("/mvp1/inbox/{}?after={}&limit={}&session_push=1&incarnation_id={id}",runtime.target_delivery_id,resume.after_inbox_seq,resume.limit.min(256))).await?;
            if router_refusal(send,id,&response).await? {return Ok(());}
            check_epoch(&response,id)?;
            response["frame_type"]=json!("resume_page");
            validation::page(&response,&runtime.target_delivery_id,resume.after_inbox_seq,resume.limit.min(256))?;
            write(send,&response).await
        }
        Client::FetchEntry {inbox_seq,..}=>{
            if inbox_seq==0 {return nack(send,id,Reason::InvalidSeq).await;}
            if inbox_seq>issued(context,runtime,id).await? {return nack(send,id,Reason::InvalidSeq).await;}
            let response=get(&context.router,&format!("/mvp1/inbox-entry/{}/{inbox_seq}?incarnation_id={id}",runtime.target_delivery_id)).await?;
            if router_refusal(send,id,&response).await? {return Ok(());}
            check_epoch(&response,id)?;
            validation::point(&response,&runtime.target_delivery_id,inbox_seq)?;
            write(send,&response).await
        }
        Client::AckBatch {inbox_seqs,..}=>batch(send,context,runtime,id,inbox_seqs,false).await,
        Client::Ack {ack,..}=>{
            let Some(seq)=ack.ext.ext.get("inbox_seq").and_then(Value::as_u64) else {return nack(send,id,Reason::InvalidSeq).await;};
            batch(send,context,runtime,id,vec![seq],true).await
        }
        Client::Nack {nack:request,..}=>{
            let Some(seq)=request.ext.ext.get("inbox_seq").and_then(Value::as_u64) else {return nack(send,id,Reason::InvalidSeq).await;};
            if seq==0 || seq>issued(context,runtime,id).await? {return nack(send,id,Reason::InvalidSeq).await;}
            let mut response=post(&context.router,"/mvp0/nack-bound",&json!({"target_delivery_id":runtime.target_delivery_id,"incarnation_id":id,"nack":request})).await?;
            if router_refusal(send,id,&response).await? {return Ok(());}
            check_epoch(&response,id)?;
            anyhow::ensure!(response["cursor"]["target_delivery_id"]==runtime.target_delivery_id,Retired);
            response["frame_type"]=json!("cursor");write(send,&response).await
        }
    }
}
async fn batch(send:&GatewaySendHandle,context:&GatewayQuicContext,runtime:&GatewaySessionRuntime,id:&str,seqs:Vec<u64>,single:bool)->anyhow::Result<()> {
    if seqs.is_empty() || seqs.len()>64 || seqs.contains(&0) || seqs.windows(2).any(|pair|pair[0]>=pair[1]) {return nack(send,id,Reason::InvalidSeq).await;}
    let published=issued(context,runtime,id).await?;
    if seqs.iter().any(|s|*s>published) {return nack(send,id,Reason::InvalidSeq).await;}
    let mut response=post(&context.router,"/mvp0/ack-bound-batch",&json!({"target_delivery_id":runtime.target_delivery_id,"incarnation_id":id,"inbox_seqs":seqs})).await?;
    if router_refusal(send,id,&response).await? {return Ok(());}
    check_epoch(&response,id)?;
    validation::batch(&response,&runtime.target_delivery_id,&seqs)?;
    if single {response.as_object_mut().ok_or(Retired)?.remove("results");}
    response["frame_type"]=json!(if single {"ack"}else{"ack_batch"});write(send,&response).await
}
/// Decode additive mesh metadata without changing the legacy public response type.
pub(crate) fn metadata(value:&Value,required:bool)->anyhow::Result<Option<(String,i64)>> {
    let id=value.get("incarnation_id").and_then(Value::as_str);
    let deadline=value.get("retain_until").and_then(Value::as_i64);
    match (id,deadline) {
        (Some(id),Some(deadline)) if ramflux_node_core::valid_inbox_incarnation(id)=>Ok(Some((id.into(),deadline))),
        (None,None) if !required=>Ok(None),
        _=>Err(Retired.into()),
    }
}
#[cfg(test)]
mod tests;
