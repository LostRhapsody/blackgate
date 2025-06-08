use openapiv3::OpenAPI;
use serde_json::Value;
use std::error::Error;
use std::fmt;
use tracing::{info, warn};

/// Custom error type for OpenAPI parsing operations
#[derive(Debug)]
pub enum OpenApiError {
    ParseError(String),
    ValidationError(String),
    FetchError(String),
}

impl fmt::Display for OpenApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenApiError::ParseError(msg) => write!(f, "OpenAPI Parse Error: {}", msg),
            OpenApiError::ValidationError(msg) => write!(f, "OpenAPI Validation Error: {}", msg),
            OpenApiError::FetchError(msg) => write!(f, "OpenAPI Fetch Error: {}", msg),
        }
    }
}

impl Error for OpenApiError {}

/// Metadata extracted from an OpenAPI specification
#[derive(Debug, Clone)]
pub struct OpenApiMetadata {
    pub title: String,
    pub description: Option<String>,
    pub auth_type: String, // Will be "none", "basic-auth", "api-key", "oauth2", "jwt", "oidc"
}

/// A route record that can be created from an OpenAPI path
#[derive(Debug, Clone)]
pub struct OpenApiRoute {
    pub path: String,
    pub upstream: String,
    pub allowed_methods: String,
    pub auth_type: String,
    pub collection_id: Option<i64>,
    pub rate_limit_per_minute: u32,
    pub rate_limit_per_hour: u32,
}

impl Default for OpenApiRoute {
    fn default() -> Self {
        Self {
            path: String::new(),
            upstream: String::new(),
            allowed_methods: String::new(),
            auth_type: "none".to_string(),
            collection_id: None,
            rate_limit_per_minute: 60,
            rate_limit_per_hour: 1000,
        }
    }
}

/// Fetches an OpenAPI specification from a URL and extracts metadata
/// 
/// # Arguments
/// * `url` - The URL to fetch the OpenAPI specification from
/// 
/// # Returns
/// * `Ok(OpenApiMetadata)` - Successfully fetched and parsed metadata
/// * `Err(OpenApiError)` - Error occurred during fetching or parsing
pub async fn fetch_and_extract_metadata(url: &str) -> Result<OpenApiMetadata, OpenApiError> {
    // Fetch the document from the URL
    let response = reqwest::get(url)
        .await
        .map_err(|e| OpenApiError::FetchError(format!("Failed to fetch from URL: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(OpenApiError::FetchError(format!(
            "HTTP {} when fetching OpenAPI spec from {}", 
            response.status(), 
            url
        )));
    }
    
    let spec_text = response.text()
        .await
        .map_err(|e| OpenApiError::FetchError(format!("Failed to read response body: {}", e)))?;
    
    // Parse the specification
    let openapi_spec = parse_openapi_spec(&spec_text)?;
    
    // Extract metadata
    extract_metadata(&openapi_spec)
}

/// Extracts metadata from a parsed OpenAPI specification
/// 
/// # Arguments
/// * `spec` - The parsed OpenAPI specification
/// 
/// # Returns
/// * `Ok(OpenApiMetadata)` - Successfully extracted metadata
/// * `Err(OpenApiError)` - Error occurred during extraction
pub fn extract_metadata(spec: &OpenAPI) -> Result<OpenApiMetadata, OpenApiError> {
    let title = spec.info.title.clone();
    let description = spec.info.description.clone();
    
    // Determine authentication type by analyzing security schemes
    let auth_type = determine_auth_type(spec);
    
    Ok(OpenApiMetadata {
        title,
        description,
        auth_type,
    })
}

/// Determines the primary authentication type from an OpenAPI specification
/// 
/// This function analyzes the security schemes and global security requirements
/// to determine the most appropriate authentication type for the API gateway.
fn determine_auth_type(spec: &OpenAPI) -> String {
    // Check if there are any security schemes defined
    let security_schemes = match &spec.components {
        Some(components) => &components.security_schemes,
        None => return "none".to_string(),
    };
    
    if security_schemes.is_empty() {
        return "none".to_string();
    }
    
    // Check global security requirements first
    if let Some(security_reqs) = spec.security.as_ref() {
        if !security_reqs.is_empty() {
            for security_req in security_reqs {
                for (scheme_name, _scopes) in security_req {
                    if let Some(scheme_ref) = security_schemes.get(scheme_name) {
                        if let Some(auth_type) = map_security_scheme_to_auth_type(scheme_ref) {
                            return auth_type;
                        }
                    }
                }
            }
        }
    }
    
    // If no global security, check the first available security scheme
    for (_name, scheme_ref) in security_schemes {
        if let Some(auth_type) = map_security_scheme_to_auth_type(scheme_ref) {
            return auth_type;
        }
    }
    
    "none".to_string()
}

/// Maps an OpenAPI security scheme to our internal authentication type
fn map_security_scheme_to_auth_type(scheme_ref: &openapiv3::ReferenceOr<openapiv3::SecurityScheme>) -> Option<String> {
    match scheme_ref {
        openapiv3::ReferenceOr::Item(scheme) => {
            match scheme {
                openapiv3::SecurityScheme::APIKey { .. } => Some("api-key".to_string()),
                openapiv3::SecurityScheme::HTTP { scheme: http_scheme, .. } => {
                    match http_scheme.to_lowercase().as_str() {
                        "basic" => Some("basic-auth".to_string()),
                        "bearer" => Some("jwt".to_string()), // Assume bearer tokens are JWT
                        _ => Some("none".to_string()),
                    }
                },
                openapiv3::SecurityScheme::OAuth2 { .. } => Some("oauth2".to_string()),
                openapiv3::SecurityScheme::OpenIDConnect { .. } => Some("oidc".to_string()),
            }
        },
        openapiv3::ReferenceOr::Reference { .. } => {
            // For now, we don't resolve references, just default to none
            Some("none".to_string())
        }
    }
}

/// Parses an OpenAPI specification document from a JSON string
/// 
/// # Arguments
/// * `spec_json` - A JSON string containing the OpenAPI specification
/// 
/// # Returns
/// * `Ok(OpenAPI)` - Successfully parsed OpenAPI specification
/// * `Err(OpenApiError)` - Error occurred during parsing
/// 
/// # Example
/// ```rust
/// use blackgate::open_api::parse_openapi_spec;
/// 
/// let spec_json = r#"
/// {
///   "openapi": "3.0.0",
///   "info": {
///     "title": "Sample API",
///     "version": "1.0.0"
///   },
///   "paths": {}
/// }
/// "#;
/// 
/// let spec = parse_openapi_spec(spec_json).unwrap();
/// assert_eq!(spec.info.title, "Sample API");
/// ```
pub fn parse_openapi_spec(spec_json: &str) -> Result<OpenAPI, OpenApiError> {
    // First parse as generic JSON to provide better error messages
    let json_value: Value = serde_json::from_str(spec_json)
        .map_err(|e| OpenApiError::ParseError(format!("Invalid JSON: {}", e)))?;
    
    // Then parse into OpenAPI struct
    let openapi_spec: OpenAPI = serde_json::from_value(json_value)
        .map_err(|e| OpenApiError::ParseError(format!("Invalid OpenAPI specification: {}", e)))?;
    
    // Basic validation
    validate_openapi_spec(&openapi_spec)?;
    
    Ok(openapi_spec)
}

/// Parses an OpenAPI specification document from a serde_json::Value
/// 
/// # Arguments
/// * `spec_value` - A serde_json::Value containing the OpenAPI specification
/// 
/// # Returns
/// * `Ok(OpenAPI)` - Successfully parsed OpenAPI specification
/// * `Err(OpenApiError)` - Error occurred during parsing
pub fn parse_openapi_spec_from_value(spec_value: Value) -> Result<OpenAPI, OpenApiError> {
    let openapi_spec: OpenAPI = serde_json::from_value(spec_value)
        .map_err(|e| OpenApiError::ParseError(format!("Invalid OpenAPI specification: {}", e)))?;
    
    validate_openapi_spec(&openapi_spec)?;
    
    Ok(openapi_spec)
}

/// Validates basic requirements of an OpenAPI specification
fn validate_openapi_spec(spec: &OpenAPI) -> Result<(), OpenApiError> {
    // Check OpenAPI version
    if !spec.openapi.starts_with("3.") {
        return Err(OpenApiError::ValidationError(
            format!("Unsupported OpenAPI version: {}. Only version 3.x is supported.", spec.openapi)
        ));
    }
    
    // Check that we have at least a title and version in info
    if spec.info.title.is_empty() {
        return Err(OpenApiError::ValidationError(
            "OpenAPI specification must have a non-empty title".to_string()
        ));
    }
    
    if spec.info.version.is_empty() {
        return Err(OpenApiError::ValidationError(
            "OpenAPI specification must have a non-empty version".to_string()
        ));
    }
    
    Ok(())
}

/// Extracts route records from an OpenAPI specification
/// 
/// # Arguments
/// * `spec` - The parsed OpenAPI specification
/// * `base_upstream_url` - The base URL where the API is hosted (e.g., "https://api.example.com")
/// * `collection_id` - Optional collection ID to associate all routes with
/// * `default_rate_limit_per_minute` - Default rate limit per minute for all routes
/// * `default_rate_limit_per_hour` - Default rate limit per hour for all routes
/// 
/// # Returns
/// * `Ok(Vec<OpenApiRoute>)` - Successfully extracted route records
/// * `Err(OpenApiError)` - Error occurred during extraction
pub fn extract_routes_from_spec(
    spec: &OpenAPI,
    base_upstream_url: &str,
    collection_id: Option<i64>,
    default_rate_limit_per_minute: u32,
    default_rate_limit_per_hour: u32,
) -> Result<Vec<OpenApiRoute>, OpenApiError> {
    let mut routes = Vec::new();
    
    // Get the default authentication type from the spec
    let default_auth_type = determine_auth_type(spec);
    
    // Parse each path in the OpenAPI spec
    for (path, path_item) in &spec.paths.paths {
        // Skip if this is a reference (we don't resolve references yet)
        let path_item = match path_item {
            openapiv3::ReferenceOr::Item(item) => item,
            openapiv3::ReferenceOr::Reference { .. } => {
                warn!("Skipping path '{}' because it's a reference (not yet supported)", path);
                continue;
            }
        };
        
        // Collect all HTTP methods available for this path
        let mut methods = Vec::new();
        
        if path_item.get.is_some() { methods.push("GET"); }
        if path_item.post.is_some() { methods.push("POST"); }
        if path_item.put.is_some() { methods.push("PUT"); }
        if path_item.delete.is_some() { methods.push("DELETE"); }
        if path_item.patch.is_some() { methods.push("PATCH"); }
        if path_item.head.is_some() { methods.push("HEAD"); }
        if path_item.options.is_some() { methods.push("OPTIONS"); }
        if path_item.trace.is_some() { methods.push("TRACE"); }
        
        // Skip paths with no operations
        if methods.is_empty() {
            warn!("Skipping path '{}' because it has no operations defined", path);
            continue;
        }
        
        // Convert OpenAPI path to our route format
        // OpenAPI uses {param} format, we might need to convert to a different format
        let route_path = convert_openapi_path_to_route_path(path);
        
        // Build the upstream URL by combining base URL with the path
        let upstream_url = format!("{}{}", base_upstream_url.trim_end_matches('/'), path);
        
        // Create a single route record for this path with all methods
        let route = OpenApiRoute {
            path: route_path,
            upstream: upstream_url,
            allowed_methods: methods.join(","),
            auth_type: default_auth_type.clone(),
            collection_id,
            rate_limit_per_minute: default_rate_limit_per_minute,
            rate_limit_per_hour: default_rate_limit_per_hour,
        };
        
        routes.push(route);
    }
    
    if routes.is_empty() {
        return Err(OpenApiError::ValidationError(
            "No valid paths found in OpenAPI specification".to_string()
        ));
    }
    
    info!("Extracted {} routes from OpenAPI specification", routes.len());
    Ok(routes)
}

/// Converts an OpenAPI path format to our route path format
/// 
/// For now, this is a simple passthrough, but we could add logic here
/// to convert OpenAPI path parameters to different formats if needed.
fn convert_openapi_path_to_route_path(openapi_path: &str) -> String {
    // OpenAPI uses {param} format
    // For now, we'll keep it as-is since our gateway can handle this format
    // In the future, we might want to convert to :param or other formats
    openapi_path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_valid_openapi_spec() {
        let spec_json = r#"
        {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0",
                "description": "A test API"
            },
            "paths": {
                "/test": {
                    "get": {
                        "summary": "Test endpoint",
                        "responses": {
                            "200": {
                                "description": "Success"
                            }
                        }
                    }
                }
            }
        }
        "#;

        let result = parse_openapi_spec(spec_json);
        assert!(result.is_ok());
        
        let spec = result.unwrap();
        assert_eq!(spec.info.title, "Test API");
        assert_eq!(spec.info.version, "1.0.0");
        assert_eq!(spec.openapi, "3.0.0");
    }

    #[test]
    fn test_parse_invalid_json() {
        let invalid_json = "{ invalid json }";
        let result = parse_openapi_spec(invalid_json);
        assert!(result.is_err());
        
        if let Err(OpenApiError::ParseError(msg)) = result {
            assert!(msg.contains("Invalid JSON"));
        } else {
            panic!("Expected ParseError");
        }
    }

    #[test]
    fn test_parse_invalid_openapi() {
        let invalid_spec = r#"
        {
            "openapi": "2.0.0",
            "info": {
                "title": "",
                "version": ""
            }
        }
        "#;

        let result = parse_openapi_spec(invalid_spec);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_from_value() {
        let spec_value = json!({
            "openapi": "3.0.0",
            "info": {
                "title": "Value API",
                "version": "2.0.0"
            },
            "paths": {}
        });

        let result = parse_openapi_spec_from_value(spec_value);
        assert!(result.is_ok());
        
        let spec = result.unwrap();
        assert_eq!(spec.info.title, "Value API");
        assert_eq!(spec.info.version, "2.0.0");
    }

    #[test]
    fn test_validation_unsupported_version() {
        let spec_json = r#"
        {
            "openapi": "2.0",
            "info": {
                "title": "Old API",
                "version": "1.0.0"
            },
            "paths": {}
        }
        "#;

        let result = parse_openapi_spec(spec_json);
        assert!(result.is_err());
        
        if let Err(OpenApiError::ValidationError(msg)) = result {
            assert!(msg.contains("Unsupported OpenAPI version"));
        } else {
            panic!("Expected ValidationError");
        }
    }

    #[test]
    fn test_validation_empty_title() {
        let spec_json = r#"
        {
            "openapi": "3.0.0",
            "info": {
                "title": "",
                "version": "1.0.0"
            },
            "paths": {}
        }
        "#;

        let result = parse_openapi_spec(spec_json);
        assert!(result.is_err());
        
        if let Err(OpenApiError::ValidationError(msg)) = result {
            assert!(msg.contains("non-empty title"));
        } else {
            panic!("Expected ValidationError");
        }
    }

    #[test]
    fn test_extract_metadata_basic() {
        let spec_json = r#"
        {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0",
                "description": "A test API for testing"
            },
            "paths": {},
            "components": {
                "securitySchemes": {
                    "basicAuth": {
                        "type": "http",
                        "scheme": "basic"
                    }
                }
            },
            "security": [
                {
                    "basicAuth": []
                }
            ]
        }
        "#;

        let spec = parse_openapi_spec(spec_json).unwrap();
        let metadata = extract_metadata(&spec).unwrap();
        
        assert_eq!(metadata.title, "Test API");
        assert_eq!(metadata.description, Some("A test API for testing".to_string()));
        assert_eq!(metadata.auth_type, "basic-auth");
    }

    #[test]
    fn test_extract_metadata_oauth2() {
        let spec_json = r#"
        {
            "openapi": "3.0.0",
            "info": {
                "title": "OAuth API",
                "version": "1.0.0"
            },
            "paths": {},
            "components": {
                "securitySchemes": {
                    "oauth2": {
                        "type": "oauth2",
                        "flows": {
                            "clientCredentials": {
                                "tokenUrl": "https://example.com/token",
                                "scopes": {}
                            }
                        }
                    }
                }
            },
            "security": [
                {
                    "oauth2": []
                }
            ]
        }
        "#;

        let spec = parse_openapi_spec(spec_json).unwrap();
        let metadata = extract_metadata(&spec).unwrap();
        
        assert_eq!(metadata.title, "OAuth API");
        assert_eq!(metadata.auth_type, "oauth2");
    }

    #[test]
    fn test_extract_metadata_no_auth() {
        let spec_json = r#"
        {
            "openapi": "3.0.0",
            "info": {
                "title": "Public API",
                "version": "1.0.0"
            },
            "paths": {}
        }
        "#;

        let spec = parse_openapi_spec(spec_json).unwrap();
        let metadata = extract_metadata(&spec).unwrap();
        
        assert_eq!(metadata.title, "Public API");
        assert_eq!(metadata.auth_type, "none");
    }

    #[test]
    fn test_extract_routes_basic() {
        let spec_json = r#"
        {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "paths": {
                "/test": {
                    "get": {
                        "summary": "Test endpoint",
                        "responses": {
                            "200": {
                                "description": "Success"
                            }
                        }
                    },
                    "post": {
                        "summary": "Create test",
                        "responses": {
                            "201": {
                                "description": "Created"
                            }
                        }
                    }
                }
            }
        }
        "#;

        let spec = parse_openapi_spec(spec_json).unwrap();
        let routes = extract_routes_from_spec(&spec, "https://api.example.com", None, 60, 1000).unwrap();
        
        assert_eq!(routes.len(), 1); // One route for the /test path
        
        let route = &routes[0];
        assert_eq!(route.path, "/test");
        assert_eq!(route.upstream, "https://api.example.com/test");
        assert_eq!(route.allowed_methods, "GET,POST");
        assert_eq!(route.auth_type, "none");
        assert_eq!(route.collection_id, None);
        assert_eq!(route.rate_limit_per_minute, 60);
        assert_eq!(route.rate_limit_per_hour, 1000);
    }

    #[test]
    fn test_extract_routes_with_collection_id() {
        let spec_json = r#"
        {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "paths": {
                "/test": {
                    "get": {
                        "summary": "Test endpoint",
                        "responses": {
                            "200": {
                                "description": "Success"
                            }
                        }
                    }
                }
            }
        }
        "#;

        let spec = parse_openapi_spec(spec_json).unwrap();
        let routes = extract_routes_from_spec(&spec, "https://api.example.com", Some(123), 60, 1000).unwrap();
        
        assert_eq!(routes.len(), 1);
        
        let route = &routes[0];
        assert_eq!(route.path, "/test");
        assert_eq!(route.upstream, "https://api.example.com/test");
        assert_eq!(route.allowed_methods, "GET");
        assert_eq!(route.auth_type, "none");
        assert_eq!(route.collection_id, Some(123));
        assert_eq!(route.rate_limit_per_minute, 60);
        assert_eq!(route.rate_limit_per_hour, 1000);
    }

    #[test]
    fn test_extract_routes_no_paths() {
        let spec_json = r#"
        {
            "openapi": "3.0.0",
            "info": {
                "title": "Empty API",
                "version": "1.0.0"
            },
            "paths": {}
        }
        "#;

        let spec = parse_openapi_spec(spec_json).unwrap();
        let result = extract_routes_from_spec(&spec, "https://api.example.com", None, 60, 1000);
        
        assert!(result.is_err());
        
        if let Err(OpenApiError::ValidationError(msg)) = result {
            assert!(msg.contains("No valid paths found"));
        } else {
            panic!("Expected ValidationError");
        }
    }

    #[test]
    fn test_extract_routes_multiple_paths() {
        let spec_json = r#"
        {
            "openapi": "3.0.0",
            "info": {
                "title": "Multi Path API",
                "version": "1.0.0"
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "responses": {
                            "200": {
                                "description": "Success"
                            }
                        }
                    },
                    "post": {
                        "summary": "Create user",
                        "responses": {
                            "201": {
                                "description": "Created"
                            }
                        }
                    }
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user",
                        "responses": {
                            "200": {
                                "description": "Success"
                            }
                        }
                    },
                    "put": {
                        "summary": "Update user",
                        "responses": {
                            "200": {
                                "description": "Updated"
                            }
                        }
                    },
                    "delete": {
                        "summary": "Delete user",
                        "responses": {
                            "204": {
                                "description": "Deleted"
                            }
                        }
                    }
                },
                "/health": {
                    "get": {
                        "summary": "Health check",
                        "responses": {
                            "200": {
                                "description": "Healthy"
                            }
                        }
                    }
                }
            }
        }
        "#;

        let spec = parse_openapi_spec(spec_json).unwrap();
        let routes = extract_routes_from_spec(&spec, "https://api.example.com", Some(42), 30, 500).unwrap();
        
        assert_eq!(routes.len(), 3); // Three paths
        
        // Check /users route
        let users_route = routes.iter().find(|r| r.path == "/users").unwrap();
        assert_eq!(users_route.upstream, "https://api.example.com/users");
        assert_eq!(users_route.allowed_methods, "GET,POST");
        assert_eq!(users_route.collection_id, Some(42));
        assert_eq!(users_route.rate_limit_per_minute, 30);
        assert_eq!(users_route.rate_limit_per_hour, 500);
        
        // Check /users/{id} route  
        let user_id_route = routes.iter().find(|r| r.path == "/users/{id}").unwrap();
        assert_eq!(user_id_route.upstream, "https://api.example.com/users/{id}");
        assert_eq!(user_id_route.allowed_methods, "GET,PUT,DELETE");
        
        // Check /health route
        let health_route = routes.iter().find(|r| r.path == "/health").unwrap();
        assert_eq!(health_route.upstream, "https://api.example.com/health");
        assert_eq!(health_route.allowed_methods, "GET");
    }

    #[test]
    fn test_extract_routes_with_authentication() {
        let spec_json = r#"
        {
            "openapi": "3.0.0",
            "info": {
                "title": "Secured API",
                "version": "1.0.0"
            },
            "paths": {
                "/secure": {
                    "get": {
                        "summary": "Secure endpoint",
                        "responses": {
                            "200": {
                                "description": "Success"
                            }
                        }
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            },
            "security": [
                {
                    "bearerAuth": []
                }
            ]
        }
        "#;

        let spec = parse_openapi_spec(spec_json).unwrap();
        let routes = extract_routes_from_spec(&spec, "https://secure.example.com", None, 10, 100).unwrap();
        
        assert_eq!(routes.len(), 1);
        
        let route = &routes[0];
        assert_eq!(route.path, "/secure");
        assert_eq!(route.upstream, "https://secure.example.com/secure");
        assert_eq!(route.allowed_methods, "GET");
        assert_eq!(route.auth_type, "jwt"); // Bearer tokens are mapped to JWT
        assert_eq!(route.rate_limit_per_minute, 10);
        assert_eq!(route.rate_limit_per_hour, 100);
    }

    #[test]
    fn test_convert_openapi_path_to_route_path() {
        // Test that OpenAPI path parameters are preserved
        assert_eq!(convert_openapi_path_to_route_path("/users/{id}"), "/users/{id}");
        assert_eq!(convert_openapi_path_to_route_path("/api/v1/items/{itemId}/details"), "/api/v1/items/{itemId}/details");
        assert_eq!(convert_openapi_path_to_route_path("/simple"), "/simple");
    }
}
