use axum::http::{HeaderMap, StatusCode};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

pub const DEFAULT_RESPONSE_CACHE_TTL: u64 = 15;

/// Represents a cached HTTP response
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub cached_at: u64,
}

/// Key used for looking up cached responses from upstreams
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct UpstreamResponseCacheKey {
    pub path: String,
    pub method: String,
    pub query: Option<String>,
    pub body_hash: u64,
}

impl Display for UpstreamResponseCacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{:x}",
            self.method,
            self.path,
            self.query.as_deref().unwrap_or(""),
            self.body_hash
        )
    }
}

impl UpstreamResponseCacheKey {
    /// Create a new cache key from request components
    pub fn new(path: &str, method: &str, query: Option<&str>, body: Option<&[u8]>) -> Self {
        let mut hasher = DefaultHasher::new();
        if let Some(b) = body {
            b.hash(&mut hasher);
        }
        let body_hash = hasher.finish();

        Self {
            path: path.to_string(),
            method: method.to_string(),
            query: query.map(|s| s.to_string()),
            body_hash,
        }
    }
}

/// Manages the response cache
#[derive(Debug)]
pub struct ResponseCache {
    pub(crate) cache: Arc<RwLock<HashMap<UpstreamResponseCacheKey, CachedResponse>>>,
    pub(crate) default_ttl: u64,
}

impl ResponseCache {
    /// Create a new ResponseCache with default TTL
    pub fn new(default_ttl: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
        }
    }

    /// Get a cached response if it exists and is not expired
    pub async fn get(&self, key: &UpstreamResponseCacheKey) -> Option<CachedResponse> {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(key) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now < cached.cached_at + self.default_ttl {
                return Some(cached.clone());
            }
        }
        None
    }

    /// Store a response in the cache
    pub async fn set(
        &self,
        key: UpstreamResponseCacheKey,
        status: StatusCode,
        headers: HeaderMap,
        body: Vec<u8>,
    ) {
        let cached_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cached = CachedResponse {
            status,
            headers,
            body,
            cached_at,
        };

        let mut cache = self.cache.write().await;
        cache.insert(key, cached);
    }

    /// Clean up expired cache entries
    pub async fn cleanup(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut cache = self.cache.write().await;
        cache.retain(|_, v| now < v.cached_at + self.default_ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};

    #[tokio::test]
    async fn test_cache_set_and_get() {
        let cache = ResponseCache::new(DEFAULT_RESPONSE_CACHE_TTL);
        let key = UpstreamResponseCacheKey::new("/test", "GET", None, None);

        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());

        // Store a response in the cache
        cache
            .set(
                key.clone(),
                StatusCode::OK,
                headers.clone(),
                b"test body".to_vec(),
            )
            .await;

        // Retrieve the cached response
        let cached = cache.get(&key).await.unwrap();

        // Verify the cached response
        assert_eq!(cached.status, StatusCode::OK);
        assert_eq!(cached.headers["content-type"], "application/json");
        assert_eq!(cached.body, b"test body");
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = ResponseCache::new(DEFAULT_RESPONSE_CACHE_TTL);
        let key = UpstreamResponseCacheKey::new("/nonexistent", "GET", None, None);

        // Try to get a non-existent key
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        // Create a cache with a very short TTL (1 second)
        let cache = ResponseCache::new(1);
        let key = UpstreamResponseCacheKey::new("/test", "GET", None, None);

        // Store a response in the cache
        cache
            .set(
                key.clone(),
                StatusCode::OK,
                HeaderMap::new(),
                b"test body".to_vec(),
            )
            .await;

        // Should be in cache initially
        assert!(cache.get(&key).await.is_some());

        // Wait for TTL to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Should be expired now
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let cache = ResponseCache::new(1); // 1 second TTL
        let key = UpstreamResponseCacheKey::new("/test", "GET", None, None);

        // Store a response in the cache
        cache
            .set(
                key.clone(),
                StatusCode::OK,
                HeaderMap::new(),
                b"test body".to_vec(),
            )
            .await;

        // Force cleanup (would normally be done by background task)
        cache.cleanup().await;

        // Should still be in cache (not expired yet)
        assert!(cache.get(&key).await.is_some());

        // Wait for TTL to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Clean up expired entries
        cache.cleanup().await;

        // Should be removed now
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_key_different_methods() {
        let key1 = UpstreamResponseCacheKey::new("/test", "GET", None, None);
        let key2 = UpstreamResponseCacheKey::new("/test", "POST", None, None);

        // These should be different cache keys
        assert_ne!(key1, key2);
    }

    #[tokio::test]
    async fn test_cache_key_different_bodies() {
        let key1 = UpstreamResponseCacheKey::new("/test", "POST", None, Some(b"body1"));
        let key2 = UpstreamResponseCacheKey::new("/test", "POST", None, Some(b"body2"));

        // These should be different cache keys
        assert_ne!(key1, key2);
    }

    #[tokio::test]
    async fn test_cache_key_different_queries() {
        let key1 = UpstreamResponseCacheKey::new("/test", "GET", Some("a=1"), None);
        let key2 = UpstreamResponseCacheKey::new("/test", "GET", Some("b=2"), None);

        // These should be different cache keys
        assert_ne!(key1, key2);
    }
}
