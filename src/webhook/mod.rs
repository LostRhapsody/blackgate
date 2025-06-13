//! # Webhook Module
//! 
//! This module provides webhook functionality for the Blackgate API Gateway service.
//! It handles webhook routes and responses for health checks and error reporting.
//! 
//! ## Features
//! 
//! - **Health Check Webhooks**: Publishes health check status as webhooks
//! - **Error Reporting Webhooks**: Exposes error information via webhooks
//! - **HTML Views**: Provides HTML views for webhook requests
//! - **JSON Responses**: Provides JSON responses for programmatic access
//! 
//! ## Modules
//! 
//! - `views`: HTML view generation for webhook responses
//! - `handlers`: Core webhook logic and request handling

pub mod views;
pub mod handlers;

use axum::Router;
use crate::AppState;

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Creates and configures webhook routes
/// 
/// This function builds a router with all webhook endpoints configured,
/// including both HTML views and JSON API endpoints for health checks
/// and error reporting.
/// 
/// # Returns
/// 
/// A configured `Router` instance with webhook routes
pub fn create_webhook_router() -> Router<AppState> {
    Router::new()
        // Health check webhook routes
        .route("/webhooks/health/view", axum::routing::get(handlers::handle_health_check_view))
        .route("/webhooks/health/json", axum::routing::get(handlers::handle_health_check_json))
        
        // Error reporting webhook routes
        .route("/webhooks/errors/view", axum::routing::get(handlers::handle_error_reporting_view))
        .route("/webhooks/errors/json", axum::routing::get(handlers::handle_error_reporting_json))
}