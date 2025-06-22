use crate::security::types::{SecretReference, SecretValue};
use std::collections::HashMap;
use tracing::{debug, info};

/// In-memory cache for secrets with TTL support
#[derive(Debug)]
pub struct SecretCache {
    cache: HashMap<SecretReference, SecretValue>,
    hit_count: u64,
    miss_count: u64,
}

impl SecretCache {
    /// Create a new empty secret cache
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// Store a secret in the cache
    pub fn store(&mut self, reference: SecretReference, value: SecretValue) {
        debug!("Caching secret: {}", reference.key);
        self.cache.insert(reference, value);
    }

    /// Get a secret from the cache if it exists and hasn't expired
    pub fn get(&mut self, reference: &SecretReference) -> Option<SecretValue> {
        if let Some(cached_value) = self.cache.get(reference) {
            if cached_value.is_expired() {
                debug!("Secret expired, removing from cache: {}", reference.key);
                self.cache.remove(reference);
                self.miss_count += 1;
                None
            } else {
                debug!("Cache hit for secret: {}", reference.key);
                self.hit_count += 1;
                Some(cached_value.clone())
            }
        } else {
            debug!("Cache miss for secret: {}", reference.key);
            self.miss_count += 1;
            None
        }
    }

    /// Remove a secret from the cache
    pub fn remove(&mut self, reference: &SecretReference) {
        debug!("Removing secret from cache: {}", reference.key);
        self.cache.remove(reference);
    }

    /// Get all secret references currently in cache
    pub fn get_all_references(&self) -> Vec<SecretReference> {
        self.cache.keys().cloned().collect()
    }

    /// Remove all expired secrets from the cache
    pub fn cleanup_expired(&mut self) {
        let expired_keys: Vec<SecretReference> = self
            .cache
            .iter()
            .filter(|(_, value)| value.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            debug!("Removing expired secret from cache: {}", key.key);
            self.cache.remove(&key);
        }

        if !self.cache.is_empty() {
            info!("Cache cleanup completed, {} secrets remaining", self.cache.len());
        }
    }

    /// Clear all secrets from the cache
    pub fn clear(&mut self) {
        info!("Clearing all secrets from cache");
        self.cache.clear();
        self.hit_count = 0;
        self.miss_count = 0;
    }

    /// Get cache statistics (total_entries, expired_entries)
    pub fn get_stats(&self) -> (usize, usize) {
        let total = self.cache.len();
        let expired = self
            .cache
            .values()
            .filter(|value| value.is_expired())
            .count();
        (total, expired)
    }

    /// Get cache hit/miss statistics
    pub fn get_hit_miss_stats(&self) -> (u64, u64, f64) {
        let total_requests = self.hit_count + self.miss_count;
        let hit_rate = if total_requests > 0 {
            self.hit_count as f64 / total_requests as f64
        } else {
            0.0
        };
        (self.hit_count, self.miss_count, hit_rate)
    }

    /// Check if a secret is cached and not expired
    pub fn contains(&self, reference: &SecretReference) -> bool {
        if let Some(cached_value) = self.cache.get(reference) {
            !cached_value.is_expired()
        } else {
            false
        }
    }

    /// Get the number of secrets currently cached
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Get all cached secrets with their TTL information
    pub fn get_cache_info(&self) -> Vec<(SecretReference, i64)> {
        self.cache
            .iter()
            .map(|(reference, value)| (reference.clone(), value.remaining_ttl()))
            .collect()
    }
}

impl Default for SecretCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::types::SecretReference;

    #[test]
    fn test_cache_basic_operations() {
        let mut cache = SecretCache::new();
        let reference = SecretReference::new(
            "test-key".to_string(),
            "project-123".to_string(),
            "dev".to_string(),
        );
        let value = SecretValue::new("test-value".to_string());

        // Test store and get
        cache.store(reference.clone(), value.clone());
        assert!(cache.contains(&reference));
        
        let retrieved = cache.get(&reference).unwrap();
        assert_eq!(retrieved.value, "test-value");

        // Test remove
        cache.remove(&reference);
        assert!(!cache.contains(&reference));
    }

    #[test]
    fn test_cache_expiry() {
        let mut cache = SecretCache::new();
        let reference = SecretReference::new(
            "test-key".to_string(),
            "project-123".to_string(),
            "dev".to_string(),
        );
        let value = SecretValue::with_ttl("test-value".to_string(), 1);

        cache.store(reference.clone(), value);
        assert!(cache.contains(&reference));

        // Wait for expiry
        std::thread::sleep(std::time::Duration::from_secs(2));
        
        // Should be expired now
        assert!(!cache.contains(&reference));
        assert!(cache.get(&reference).is_none());
    }

    #[test]
    fn test_cache_stats() {
        let mut cache = SecretCache::new();
        let reference = SecretReference::new(
            "test-key".to_string(),
            "project-123".to_string(),
            "dev".to_string(),
        );
        let value = SecretValue::new("test-value".to_string());

        cache.store(reference.clone(), value);
        
        // Test hit
        cache.get(&reference);
        let (hits, misses, hit_rate) = cache.get_hit_miss_stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 0);
        assert_eq!(hit_rate, 1.0);

        // Test miss
        let other_reference = SecretReference::new(
            "other-key".to_string(),
            "project-123".to_string(),
            "dev".to_string(),
        );
        cache.get(&other_reference);
        let (hits, misses, hit_rate) = cache.get_hit_miss_stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
        assert_eq!(hit_rate, 0.5);
    }
}