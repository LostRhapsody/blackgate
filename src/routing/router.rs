
//! # Router Module
//! 
//! This module provides HTTP routing functionality for the Blackgate application.
//! It creates and configures an Axum router with comprehensive HTTP method support
//! and middleware integration.
//! 
//! ## Features
//! 
//! - **Multi-method routing**: Supports GET, HEAD, DELETE, POST, PUT, and PATCH methods
//! - **Catch-all routing**: Uses wildcard path matching (`/*path`) for flexible request handling
//! - **Web integration**: Merges with web-specific routes through `web::create_web_router()`
//! - **Observability**: Includes HTTP tracing layer for monitoring and debugging
//! - **State management**: Integrates with application state for shared data access
//! 
//! ## Usage
//! 
//! The primary entry point is the `create_router()` function which builds a complete
//! router instance with all necessary middleware and route handlers configured.
//! 
//! ## Architecture
//! 
//! The router follows a layered architecture:
//! 1. Web routes (specific routes merged first)
//! 2. Catch-all routes for each HTTP method
//! 3. Application state injection
//! 4. HTTP tracing middleware

use axum::{Router, routing::{get, post, put, delete, patch, head}};
use tower_http::trace::TraceLayer;
use crate::web;
use super::handlers::{handle_get_request, handle_head_request, handle_delete_request, handle_post_request, handle_put_request, handle_patch_request};
use crate::AppState;

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .merge(web::create_web_router())
        .route("/{*path}", get(handle_get_request))
        .route("/{*path}", head(handle_head_request))
        .route("/{*path}", delete(handle_delete_request))
        .route("/{*path}", post(handle_post_request))
        .route("/{*path}", put(handle_put_request))
        .route("/{*path}", patch(handle_patch_request))
        .route("/health", get(|| async { "OK" }))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////
// Tests for the router are in the tests module