//! Authenticated application routes, dispatched inside the Oak session only.
use crate::{
    attestation::evidence::Keyset,
    auth::User,
    inference::{
        error::ApiError,
        request::{ChatRequest, ClientChatContent, validate_chat},
        stream,
    },
    services::chat::ChatService,
};
use axum::{
    Extension, Json, Router,
    body::to_bytes,
    extract::{Request, State},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::post,
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub fn router(service: Arc<ChatService>) -> Router {
    Router::new()
        .route("/v3/chat/completions", post(chat))
        .route("/v3/chat/title", post(title))
        .with_state(service)
}

async fn chat(
    State(state): State<Arc<ChatService>>,
    Extension(identity): Extension<Arc<Keyset>>,
    user: User,
    request: Request,
) -> Result<Response, ApiError> {
    let received = read_json(request, 64 * 1024 * 1024).await?;
    let input: ChatRequest = serde_json::from_slice(&received)
        .map_err(|_| ApiError::BadRequest("Invalid chat request".into()))?;
    validate_chat(&input)?;
    let admission = state.admit(user.id()).await?;
    if !admission.plan.is_pro()
        && input
            .messages
            .iter()
            .any(|m| matches!(m.content, ClientChatContent::Parts(_)))
    {
        return Err(ApiError::Forbidden);
    }
    let model = ChatService::resolve_model(input.model.as_deref(), admission.plan)?;
    let mut messages = vec![json!({
        "role": "system",
        "content": input.system_prompt(&state.config.system_prompt),
    })];
    for message in &input.messages {
        messages.push(serde_json::to_value(message).map_err(|_| ApiError::Unavailable)?);
    }
    let mut forwarded = state.request_body(
        user.id(),
        model,
        &messages,
        state.config.temperature,
        state.config.max_tokens,
    )?;
    input.apply_options(admission.plan, &mut forwarded)?;
    let forwarded = serde_json::to_vec(&forwarded).map_err(|_| ApiError::Unavailable)?;
    let (response, receipt) = state
        .identity
        .open_inference(
            &identity,
            "/v3/chat/completions",
            input.model.as_deref(),
            &received,
            forwarded,
        )
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let mut events = stream::decode(response).map_err(|_| ApiError::Unavailable)?;
    let user_id = user.id().to_owned();
    let body = async_stream::try_stream! {
        let _permit = admission.permit;
        let mut usage = None;
        while let Some(item) = events.next().await {
            match item {
                Ok(stream::Event::Chunk(value)) => yield Event::default().event("chunk").json_data(value)
                    .map_err(|_| std::io::Error::other("inference encoding failed"))?,
                Ok(stream::Event::Usage(metrics)) => usage = Some(metrics),
                Err(_) => {
                    yield Event::default().event("error").data(r#"{"code":"inference_failed"}"#);
                    Err(std::io::Error::other("inference interrupted"))?;
                }
            }
        }
        let usage = usage.ok_or_else(|| std::io::Error::other("inference usage missing"))?;
        admission.accounting.commit(input.request_id, user_id, model.into(), usage);
        yield Event::default().event("done").data("{}");
    };
    let body: std::pin::Pin<
        Box<dyn futures_util::Stream<Item = Result<Event, std::io::Error>> + Send>,
    > = Box::pin(body);
    let response = Sse::new(body)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response();
    Ok(state.identity.clone().sign_response(receipt, response))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TitleRequest {
    request_id: Uuid,
    message: String,
}

async fn title(
    State(state): State<Arc<ChatService>>,
    Extension(identity): Extension<Arc<Keyset>>,
    user: User,
    request: Request,
) -> Result<Response, ApiError> {
    let received = read_json(request, 128 * 1024).await?;
    let input: TitleRequest = serde_json::from_slice(&received)
        .map_err(|_| ApiError::BadRequest("Invalid title request".into()))?;
    let message = input.message.trim();
    if message.is_empty() || message.len() > 12000 {
        return Err(ApiError::BadRequest(
            "message must contain 1..12000 bytes".into(),
        ));
    }
    let admission = state.admit(user.id()).await?;
    let messages = vec![
        json!({"role":"system", "content":crate::services::chat::TITLE_PROMPT}),
        json!({"role":"user", "content":message}),
    ];
    let forwarded =
        state.request_body(user.id(), crate::inference::GLM_MODEL, &messages, 0.2, 64)?;
    let forwarded = serde_json::to_vec(&forwarded).map_err(|_| ApiError::Unavailable)?;
    let (response, receipt) = state
        .identity
        .open_inference(&identity, "/v3/chat/title", None, &received, forwarded)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    let mut events = stream::decode(response).map_err(|_| ApiError::Unavailable)?;
    let mut content = String::new();
    let mut usage = None;
    while let Some(item) = events.next().await {
        match item.map_err(|_| ApiError::Unavailable)? {
            stream::Event::Chunk(value) => {
                if let Some(text) = value
                    .pointer("/choices/0/delta/content")
                    .and_then(serde_json::Value::as_str)
                {
                    if content.len().saturating_add(text.len()) > 16000 {
                        return Err(ApiError::Unavailable);
                    }
                    content.push_str(text);
                }
            }
            stream::Event::Usage(metrics) => usage = Some(metrics),
        }
    }
    let title = crate::services::chat::normalize_title(&content)?;
    admission.accounting.commit(
        input.request_id,
        user.id().into(),
        crate::inference::GLM_MODEL.into(),
        usage.ok_or(ApiError::Unavailable)?,
    );
    Ok(state
        .identity
        .clone()
        .sign_response(receipt, Json(json!({"title":title})).into_response()))
}

async fn read_json(request: Request, limit: usize) -> Result<axum::body::Bytes, ApiError> {
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(';').next())
        .map(str::trim);
    if !content_type.is_some_and(|s| s.eq_ignore_ascii_case("application/json")) {
        return Err(ApiError::BadRequest(
            "Content-Type must be application/json".into(),
        ));
    }
    to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| ApiError::BadRequest("Request body exceeds limit".into()))
}
