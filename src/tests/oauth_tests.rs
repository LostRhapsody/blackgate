//! Integration tests for OAuth 2.0 implementation
use assert_cmd::Command;
use predicates::str::contains;
use std::process::Command as StdCommand;
use std::thread;
use std::time::Duration;
use reqwest::Client;
use tokio::runtime::Runtime;

/// Test the OAuth 2.0 client credentials flow
#[test]
fn test_oauth_client_credentials_flow() {
    // Start the BlackGate server with the OAuth test server via the StartOAuthTestServer command
    let mut child = StdCommand::new("cargo")
        .args(["run", "--", "start-o-auth-test-server"])
        .spawn()
        .expect("Failed to start blackgate with OAuth test server");
    
    // Wait for both servers to start
    thread::sleep(Duration::from_secs(3));
    
    // Create a runtime for making async HTTP requests
    let rt = Runtime::new().unwrap();
    
    // First test: try accessing the OAuth info endpoint directly
    let client = Client::new();
    let info_response = rt.block_on(async {
        client.get("http://localhost:3001/oauth/info")
            .send()
            .await
    });
    
    // Ensure the OAuth test server is running
    assert!(info_response.is_ok(), "OAuth test server should be running");
    
    if let Ok(response) = info_response {
        assert_eq!(response.status().as_u16(), 200);
        let text = rt.block_on(async { response.text().await.unwrap_or_default() });
        assert!(text.contains("OAuth 2.0 Test Server - Info Endpoint"));
    }

    // Second test: try accessing a protected route through the gateway
    // test the protected route via the gateway
    let gateway_response = rt.block_on(async {
        client.get("http://localhost:3000/oauth-test")
            .send()
            .await
    });
    
    // Validate the response
    if let Ok(response) = gateway_response {
        assert_eq!(response.status().as_u16(), 200, "Expected 200 OK from gateway");        
    } else {
        panic!("Failed to get a response from the gateway");
    }
    
    // Clean up - terminate the server process
    let _ = child.kill();
}
