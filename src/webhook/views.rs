//! # Webhook Views Module
//!
//! This module provides HTML view generation for webhook responses.
//! It contains functions to build HTML representations of health checks
//! and error reports that can be consumed by monitoring services or
//! displayed in web interfaces.
//!
//! ## Features
//!
//! - **Health Check Views**: HTML representation of system health status
//! - **Error Reporting Views**: HTML formatted error information

use sqlx;

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Builds an HTML view for health check status
///
/// This function generates an HTML representation of the current system
/// health status that can be consumed by monitoring services or displayed
/// in web browsers.
///
/// # Arguments
///
/// * `health_checks` - A slice of SQLite rows containing health check data
///
/// # Returns
///
/// A `String` containing the HTML representation of health check data
pub fn build_health_check_view(health_checks: &[sqlx::sqlite::SqliteRow]) -> String {
    use sqlx::Row;

    let mut healthy_count = 0;
    let mut unhealthy_count = 0;
    let mut unknown_count = 0;

    // Calculate summary statistics
    for row in health_checks {
        match row.get::<String, _>("health_check_status").as_str() {
            "Healthy" => healthy_count += 1,
            "Unhealthy" => unhealthy_count += 1,
            _ => unknown_count += 1,
        }
    }

    let total_routes = health_checks.len();

    // if we have no unhealthy or unknown routes, status is healthy.
    // if we have more health routes than unhealthy or unknown, status is "ok"
    // if we have ALL unknown routes, status is "unknown"
    // otherwise, status is unhealthy.
    let overall_status = if healthy_count == total_routes {
        "Healthy"
    } else if healthy_count > unhealthy_count + unknown_count {
        "Degraded"
    } else if unknown_count == total_routes {
        "Unknown"
    } else {
        "Unhealthy"
    };

    // Generate health check rows HTML
    let health_rows: String = health_checks
        .iter()
        .map(|row| {
            let path = row.get::<String, _>("path");
            let status = row.get::<String, _>("health_check_status");
            let response_time = row
                .get::<Option<i64>, _>("response_time_ms")
                .map(|t| format!("{}ms", t))
                .unwrap_or_else(|| "N/A".to_string());
            let error_message = row
                .get::<Option<String>, _>("error_message")
                .unwrap_or_else(|| String::new());
            let checked_at = row.get::<String, _>("checked_at");
            let method = row.get::<String, _>("method_used");

            let health_indicator = match status.as_str() {
                "Healthy" => r#"<span class="health-indicator health-green">●</span>"#,
                "Unhealthy" => r#"<span class="health-indicator health-red">●</span>"#,
                _ => r#"<span class="health-indicator health-yellow">●</span>"#,
            };

            let error_row = if !error_message.is_empty() && status == "Unhealthy" {
                format!(
                    r#"<tr class="error-row"><td colspan="5">{}</td></tr>"#,
                    error_message
                )
            } else {
                String::new()
            };

            format!(
                r#"
        <tr>
            <td>{}{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
        </tr>{}"#,
                health_indicator, path, status, response_time, method, checked_at, error_row
            )
        })
        .collect();

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Health Check - Blackgate API Gateway</title>
    <meta charset="utf-8">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <nav>
        <div class="nav-header">
            <h1>Blackgate API Gateway - Health Status</h1>
            <div class="header-links">
                <a href="/" class="header-link">
                    <svg viewBox="0 0 24 24" fill="currentColor">
                        <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
                        <polyline points="9,22 9,12 15,12 15,22"/>
                    </svg>
                    Dashboard
                </a>
                <a href="/webhooks/health/json" class="header-link">
                    <svg viewBox="0 0 24 24" fill="currentColor">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                        <polyline points="14,2 14,8 20,8"/>
                        <line x1="16" y1="13" x2="8" y2="13"/>
                        <line x1="16" y1="17" x2="8" y2="17"/>
                        <polyline points="10,9 9,9 8,9"/>
                    </svg>
                    JSON API
                </a>
            </div>
        </div>
    </nav>

    <div class="dashboard-container">
        <div class="dashboard-summary">
            <div class="dashboard-header">
                <h2>Health Check Summary</h2>
                <span class="health-indicator {}">Overall Status: {}</span>
            </div>
            
            <div class="stats-grid">
                <div class="stat-item">
                    <label>Total Routes</label>
                    <span>{}</span>
                </div>
                <div class="stat-item">
                    <label>Healthy Routes</label>
                    <span class="health-green">{}</span>
                </div>
                <div class="stat-item">
                    <label>Unhealthy Routes</label>
                    <span class="health-red">{}</span>
                </div>
                <div class="stat-item">
                    <label>Unknown Status</label>
                    <span class="health-yellow">{}</span>
                </div>
            </div>
        </div>

        <div class="dashboard-section">
            <h3>Route Health Details</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Route Path</th>
                        <th>Status</th>
                        <th>Response Time</th>
                        <th>Method</th>
                        <th>Last Checked</th>
                    </tr>
                </thead>
                <tbody>
                    {}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>"#,
        // unknown and degraded are both yellow
        match overall_status {
            "Healthy" => "health-green",
            "Unhealthy" => "health-red",
            _ => "health-yellow",
        },
        overall_status,
        total_routes,
        healthy_count,
        unhealthy_count,
        unknown_count,
        health_rows
    )
}

/// Builds an HTML view for error reporting
///
/// This function generates an HTML representation of recent errors
/// and error statistics that can be consumed by monitoring services
/// or displayed in web interfaces.
///
/// # Returns
///
/// A `String` containing the HTML representation of error report data
///
/// # TODO
///
/// Implement the actual error reporting view generation logic
pub fn build_error_reporting_view() -> String {
    // Placeholder implementation
    r#"<!DOCTYPE html>
<html>
<head>
    <title>Error Report - Blackgate API Gateway</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .error-summary { padding: 10px; background-color: #f8f9fa; border-radius: 5px; margin-bottom: 20px; }
        .error-item { padding: 10px; border-left: 4px solid #dc3545; margin-bottom: 10px; background-color: #f8d7da; }
        .timestamp { color: #6c757d; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>Blackgate API Gateway - Error Report</h1>
    <div class="error-summary">
        <h2>Error Summary</h2>
        <p>Total errors in last 24h: [Count placeholder]</p>
        <p>Last updated: [Timestamp placeholder]</p>
    </div>
    <div class="error-item">
        <h3>Sample Error</h3>
        <p>Error message: [Placeholder error message]</p>
        <p class="timestamp">Timestamp: [Timestamp placeholder]</p>
    </div>
    <!-- TODO: Implement actual error data display -->
</body>
</html>"#.to_string()
}
