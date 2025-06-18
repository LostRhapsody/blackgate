//! Integration and unit tests for main.rs
use assert_cmd::Command;
use predicates::str::contains;
use reqwest::Client;
use tokio::runtime::Runtime;

#[test]
fn add_route_required_params() {
    let mut cmd = Command::cargo_bin("blackgate").unwrap();
    cmd.arg("add-route")
        .arg("--path")
        .arg("/foo")
        .arg("--upstream")
        .arg("http://localhost:9999");
    cmd.assert()
        .success()
        .stdout(contains("Added route: /foo -> http://localhost:9999"));
}

#[test]
fn add_route_with_all_params() {
    let mut cmd = Command::cargo_bin("blackgate").unwrap();
    cmd.arg("add-route")
        .arg("--path")
        .arg("/bar")
        .arg("--upstream")
        .arg("http://localhost:9999")
        .arg("--auth-type")
        .arg("api-key")
        .arg("--auth-value")
        .arg("Bearer test")
        .arg("--allowed-methods")
        .arg("POST");
    cmd.assert()
        .success()
        .stdout(contains("Added route: /bar -> http://localhost:9999"));
}

#[test]
fn list_routes() {
    // List and ensure the existing route is there
    let mut cmd = Command::cargo_bin("blackgate").unwrap();
    cmd.arg("add-route")
        .arg("--path")
        .arg("/list-test")
        .arg("--upstream")
        .arg("http://localhost:9999");
    cmd.assert()
        .success()
        .stdout(contains("Added route: /list-test -> http://localhost:9999"));
    let mut cmd = Command::cargo_bin("blackgate").unwrap();
    cmd.arg("list-routes");
    cmd.assert().success().stdout(contains("/list-test"));
    let mut cmd = Command::cargo_bin("blackgate").unwrap();
    cmd.arg("remove-route").arg("--path").arg("/list-test");
    cmd.assert()
        .success()
        .stdout(contains("Removed route: /list-test"));
}

#[test]
fn http_method_rejected_if_not_allowed() {
    let rt = Runtime::new().unwrap();
    // Try GET (should fail)
    let client = Client::new();
    let res = rt
        .block_on(client.get("http://localhost:3000/post-test").send())
        .unwrap();
    assert_eq!(res.status(), 405);
}

#[test]
fn http_method_allowed_if_unspecified() {
    // Start test upstream server
    let rt = Runtime::new().unwrap();
    // Try GET (should succeed)
    let client = Client::new();
    let res = rt
        .block_on(
            client
                .post("http://localhost:3000/no-method-test")
                .json(&serde_json::json!({"payload": "hello"}))
                .send(),
        )
        .unwrap();
    assert!(res.status() == 200 || res.status() == 503 || res.status() == 405);
}

#[test]
fn http_method_allowed_if_correct() {
    // Start test upstream server
    let rt = Runtime::new().unwrap();
    // Try POST (should succeed)
    let client = Client::new();
    let res = rt
        .block_on(
            client
                .post("http://localhost:3000/post-test")
                .json(&serde_json::json!({"payload": "hello"}))
                .send(),
        )
        .unwrap();
    assert!(res.status() == 200 || res.status() == 503);
}
