use openapiv3::OpenAPI;
use serde_json::Value;
use std::error::Error;
use std::fmt;

/// Custom error type for OpenAPI parsing operations
#[derive(Debug)]
pub enum OpenApiError {
    ParseError(String),
    ValidationError(String),
}

impl fmt::Display for OpenApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenApiError::ParseError(msg) => write!(f, "OpenAPI Parse Error: {}", msg),
            OpenApiError::ValidationError(msg) => write!(f, "OpenAPI Validation Error: {}", msg),
        }
    }
}

impl Error for OpenApiError {}

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
}
