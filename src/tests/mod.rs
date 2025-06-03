//! Integration and unit tests for main.rs
use assert_cmd::Command;
use predicates::str::contains;
use std::process::Command as StdCommand;
use std::thread;
use std::time::Duration;
use reqwest::Client;
use tokio::runtime::Runtime;
use sqlx::SqlitePool;

// Helper to reset DB before each test
fn reset_db() {
    // Initialize SQLite database
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pool = rt.block_on(SqlitePool::connect("sqlite://blackgate.db"))
        .expect("Failed to connect to SQLite");

    // Create routes table if it doesn't exist
    rt.block_on(sqlx::query(
        "drop table if exists routes;
        CREATE TABLE IF NOT EXISTS routes (
            path TEXT PRIMARY KEY,
            auth_type TEXT,
            auth_value TEXT,
            allowed_methods TEXT,
            upstream TEXT NOT NULL
        )
        ;
        INSERT INTO routes (path, upstream, auth_type, auth_value, allowed_methods) 
        VALUES ('/warehouse-post', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','POST')
        VALUES ('/warehouse-get', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','GET')
        VALUES ('/warehouse-none', 'https://httpbin.org/post', 'api-key', 'Bearer warehouse_key','')
        ",
    )
    .execute(&pool))
    .expect("Failed to create routes table");
}

#[test]
fn add_route_required_params() {
    let mut cmd = Command::cargo_bin("blackgate").unwrap();
    cmd.arg("add-route")
        .arg("--path").arg("/foo")
        .arg("--upstream").arg("http://localhost:9999");
    cmd.assert().success().stdout(contains("Added route: /foo -> http://localhost:9999"));
}

#[test]
fn add_route_with_all_params() {
    let mut cmd = Command::cargo_bin("blackgate").unwrap();
    cmd.arg("add-route")
        .arg("--path").arg("/bar")
        .arg("--upstream").arg("http://localhost:9999")
        .arg("--auth-type").arg("api-key")
        .arg("--auth-value").arg("Bearer test")
        .arg("--allowed-methods").arg("POST");
    cmd.assert().success().stdout(contains("Added route: /bar -> http://localhost:9999"));
}

#[test]
fn list_routes() {
    // List and ensure the existing route is there
    let mut cmd = Command::cargo_bin("blackgate").unwrap();
    cmd.arg("list-routes");
    cmd.assert().success().stdout(contains("/warehouse"));
}

#[test]
fn http_method_rejected_if_not_allowed() {
    // Start test upstream server
    let rt = Runtime::new().unwrap();
    let (_addr, shutdown) = rt.block_on(crate::test_server::spawn_test_server());
    // Start blackgate server
    let mut child = StdCommand::new("cargo")
        .args(["run", "--", "start"])
        .spawn()
        .expect("Failed to start blackgate");
    thread::sleep(Duration::from_secs(2));
    // Try GET (should fail)
    let client = Client::new();
    let res = rt.block_on(client.get("http://localhost:3000/warehouse").send()).unwrap();
    assert_eq!(res.status(), 405);
    // Shutdown
    let _ = shutdown.send(());
    let _ = child.kill();
}

#[test]
fn http_method_allowed_if_unspecified() {
    // Start test upstream server
    let rt = Runtime::new().unwrap();
    let (_addr, shutdown) = rt.block_on(crate::test_server::spawn_test_server());
    // Start blackgate server
    let mut child = StdCommand::new("cargo")
        .args(["run", "--", "start"])
        .spawn()
        .expect("Failed to start blackgate");
    thread::sleep(Duration::from_secs(2));
    // Try GET (should succeed)
    let client = Client::new();
    let res = rt.block_on(client.post("http://localhost:3000/warehouse").json(&serde_json::json!({"payload": "hello"})).send()).unwrap();
    assert_ne!(res.status(), 405);
    // Shutdown
    let _ = shutdown.send(());
    let _ = child.kill();
}

#[test]
fn http_method_allowed_if_correct() {
    // Start test upstream server
    let rt = Runtime::new().unwrap();
    let (_addr, shutdown) = rt.block_on(crate::test_server::spawn_test_server());
    // Start blackgate server
    let mut child = StdCommand::new("cargo")
        .args(["run", "--", "start"])
        .spawn()
        .expect("Failed to start blackgate");
    thread::sleep(Duration::from_secs(2));
    // Try POST (should succeed)
    let client = Client::new();
    let res = rt.block_on(client.post("http://localhost:3000/warehouse").json(&serde_json::json!({"payload": "hello"})).send()).unwrap();
    assert_eq!(res.status(), 200);
    // Shutdown
    let _ = shutdown.send(());
    let _ = child.kill();
}
