# Agent Guidelines for Blackgate

## Build/Test Commands
- `cargo build` - Build the project
- `cargo test` - Run all tests
- `cargo test <test_name>` - Run a specific test
- `cargo clippy` - Run linter
- `cargo fmt` - Format code
- `cargo run` - Run the application

## Code Style
- Use comprehensive module documentation with `//!` at the top of each file
- Include feature descriptions, usage examples, and sub-module listings in docs
- Follow Rust naming conventions: snake_case for functions/variables, PascalCase for types
- Use `tracing` crate for logging (info!, warn!, error!, debug!)
- Prefer explicit error handling with Result types over unwrap/expect
- Use structured imports: std first, external crates, then local modules
- Add inline comments for complex logic, avoid obvious comments
- Use `#[derive(Clone)]` for shared state structs
- Prefer Arc<Mutex<T>> or Arc<RwLock<T>> for thread-safe shared data

## Architecture
- Main modules: auth, routing, metrics, rate_limiter, cli, server, database, web, webhook
- Use AppState struct for shared application state (DB pool, caches, etc.)
- Authentication supports: API Key, Basic Auth, OAuth 2.0, JWT, OIDC
- Database: SQLite with manual migrations, never automatic
- Use sqlx for database operations with connection pooling