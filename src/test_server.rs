use axum::{routing::post, Router, Json};
use std::net::SocketAddr;
use tokio::sync::oneshot;
use serde::Deserialize;

#[derive(Deserialize)]
struct PostRequest {
    payload: String,
}

async fn echo(Json(payload): Json<PostRequest>) -> String {
    payload.payload
}

pub async fn spawn_test_server() -> (SocketAddr, oneshot::Sender<()>) {
    let app = Router::new().route("/", post(echo));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async { rx.await.ok(); })
            .await
            .unwrap();
    });
    (addr, tx)
}
