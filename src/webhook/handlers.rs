//! # Webhook Handlers Module
//!
//! This module contains all the webhook logic and request handling for
//! the Blackgate API Gateway service. It provides both HTML view handlers
//! and JSON API handlers for health checks and error reporting.
//!
//! ## Features
//!
//! - **Health Check Handlers**: Process health check webhook requests
//! - **Error Reporting Handlers**: Process error reporting webhook requests
//! - **Multiple Response Formats**: Support for both HTML views and JSON responses

use super::views;
use crate::AppState;
use crate::database::queries;
use axum::{
    extract::State,
    response::{Html, Json},
};
use chrono;
use serde_json::{Value, json};
use sqlx::Row;

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Handles health check view requests
///
/// This handler processes requests for the health check HTML view endpoint.
/// It generates an HTML representation of the current system health status.
///
/// # Arguments
///
/// * `State(state)` - The application state containing health check data
///
/// # Returns
///
/// An `Html<String>` response containing the health check view
pub async fn handle_health_check_view(State(state): State<AppState>) -> Html<String> {
    // Fetch health check data from database
    let health_checks = queries::fetch_all_health_checks(&state.db)
        .await
        .unwrap_or_else(|_| Vec::new());

    let html_content = views::build_health_check_view(&health_checks);
    Html(html_content)
}

/// Handles error reporting view requests
///
/// This handler processes requests for the error reporting HTML view endpoint.
/// It generates an HTML representation of recent errors and error statistics.
///
/// # Arguments
///
/// * `State(state)` - The application state containing error data
///
/// # Returns
///
/// An `Html<String>` response containing the error reporting view
pub async fn handle_error_reporting_view(State(state): State<AppState>) -> Html<String> {
    // Fetch error logs from database
    let error_logs = queries::fetch_all_error_logs(&state.db)
        .await
        .unwrap_or_else(|_| Vec::new());

    let html_content = views::build_error_reporting_view(&error_logs);
    Html(html_content)
}

/// Handles health check JSON requests
///
/// This handler processes requests for the health check JSON API endpoint.
/// It returns health check data in JSON format for programmatic consumption.
///
/// # Arguments
///
/// * `State(state)` - The application state containing health check data
///
/// # Returns
///
/// A `Json<Value>` response containing health check data in JSON format
pub async fn handle_health_check_json(State(state): State<AppState>) -> Json<Value> {
    use sqlx::Row;

    // Fetch health check data from database
    let health_checks = queries::fetch_all_health_checks(&state.db)
        .await
        .unwrap_or_else(|_| Vec::new());

    // Convert to JSON format
    let health_data: Vec<Value> = health_checks
        .iter()
        .map(|row| {
            json!({
                "path": row.get::<String, _>("path"),
                "status": row.get::<String, _>("health_check_status"),
                "response_time_ms": row.get::<Option<i64>, _>("response_time_ms"),
                "error_message": row.get::<Option<String>, _>("error_message"),
                "checked_at": row.get::<String, _>("checked_at"),
                "method_used": row.get::<String, _>("method_used")
            })
        })
        .collect();

    let response_data = json!({
        "summary": {
            "total_routes": health_data.len(),
            "healthy_routes": health_data.iter().filter(|h| h["status"] == "Healthy").count(),
            "unhealthy_routes": health_data.iter().filter(|h| h["status"] == "Unhealthy").count(),
            "unknown_routes": health_data.iter().filter(|h| h["status"] == "Unknown").count(),
            "last_updated": chrono::Utc::now().to_rfc3339()
        },
        "health_checks": health_data
    });

    Json(response_data)
}

/// Handles error reporting JSON requests
///
/// This handler processes requests for the error reporting JSON API endpoint.
/// It returns error data in JSON format for programmatic consumption.
///
/// # Arguments
///
/// * `State(state)` - The application state containing error data
///
/// # Returns
///
/// A `Json<Value>` response containing error data in JSON format
pub async fn handle_error_reporting_json(State(state): State<AppState>) -> Json<Value> {
    // Fetch error logs from database
    let error_logs = queries::fetch_all_error_logs(&state.db)
        .await
        .unwrap_or_else(|_| Vec::new());
    // Transform database rows into JSON format
    let error_data: Vec<Value> = error_logs
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<String, _>("id"),
                "message": row.get::<String, _>("error_message"),
                "severity": row.get::<String, _>("severity"),
                "context": row.get::<Option<String>, _>("context"),
                "file_location": row.get::<Option<String>, _>("file_location"),
                "line_number": row.get::<Option<i64>, _>("line_number"),
                "function_name": row.get::<Option<String>, _>("function_name"),
                "timestamp": row.get::<String, _>("created_at")
            })
        })
        .collect();

    let response_data = json!({
        "summary": {
            "total_errors": error_data.len(),
            "last_updated": chrono::Utc::now().to_rfc3339()
        },
        "error_logs": error_data
    });

    Json(response_data)
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////
// Tests for webhook handlers are located in the tests module
