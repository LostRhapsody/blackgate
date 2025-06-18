//! # Logging Module
//!
//! This module provides centralized logging functionality for the Blackgate API Gateway.
//! It handles error logging with database persistence and automatic cleanup.
//!
//! ## Features
//!
//! - **Error Logging**: Persistent error storage in database
//! - **Automatic Cleanup**: Background cleanup of old error records
//! - **Non-blocking Operations**: Async error logging that doesn't impact performance

pub mod errors;
