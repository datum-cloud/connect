use std::{borrow::Cow, env};

use serde::{Deserialize, Serialize};

const STAGING_API_URL: &str = "https://api.staging.env.datum.net";
const PROD_API_URL: &str = "https://api.datum.net";

/// Environment for Datum API. Use [`ApiEnv::from_env()`] or `ApiEnv::default()` to respect `DATUM_API_ENV`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiEnv {
    Staging,
    Production,
    /// Custom API host (plugin mode override).
    Custom { api_url: String },
}

impl ApiEnv {
    /// Uses `DATUM_API_ENV`: `staging` → Staging, anything else (including unset) → Production.
    pub fn from_env() -> Self {
        match env::var("DATUM_API_ENV").as_deref() {
            Ok("staging") => ApiEnv::Staging,
            _ => ApiEnv::Production,
        }
    }

    /// Checks `DATUM_API_HOST` first, falls back to `from_env()`.
    ///
    /// In plugin mode, the Go plugin sets `DATUM_API_HOST` to point at a
    /// specific API host. This method honors that override.
    pub fn from_env_with_host_override() -> Self {
        if let Ok(host) = env::var("DATUM_API_HOST") {
            return ApiEnv::Custom { api_url: host };
        }
        Self::from_env()
    }

    pub fn api_url(&self) -> Cow<'static, str> {
        match self {
            ApiEnv::Staging => Cow::Borrowed(STAGING_API_URL),
            ApiEnv::Production => Cow::Borrowed(PROD_API_URL),
            ApiEnv::Custom { api_url } => Cow::Owned(api_url.clone()),
        }
    }
}

impl Default for ApiEnv {
    fn default() -> Self {
        Self::from_env()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cleanup_env() {
        unsafe {
            std::env::remove_var("DATUM_API_ENV");
            std::env::remove_var("DATUM_API_HOST");
        }
    }

    #[test]
    fn from_env_defaults_to_production() {
        cleanup_env();
        let env = ApiEnv::from_env();
        assert!(matches!(env, ApiEnv::Production));
    }

    #[test]
    fn from_env_staging_when_set() {
        cleanup_env();
        unsafe { std::env::set_var("DATUM_API_ENV", "staging"); }
        let env = ApiEnv::from_env();
        assert!(matches!(env, ApiEnv::Staging));
    }

    #[test]
    fn from_env_with_host_override_uses_datum_api_host() {
        cleanup_env();
        unsafe { std::env::set_var("DATUM_API_HOST", "https://custom.example.com"); }
        let env = ApiEnv::from_env_with_host_override();
        assert!(matches!(&env, ApiEnv::Custom { api_url } if api_url == "https://custom.example.com"));
    }

    #[test]
    fn api_url_custom_returns_host() {
        let env = ApiEnv::Custom { api_url: "https://my.api.com".to_string() };
        assert_eq!(env.api_url(), "https://my.api.com");
    }

    #[test]
    fn api_url_staging_returns_staging_url() {
        assert_eq!(ApiEnv::Staging.api_url(), STAGING_API_URL);
    }

    #[test]
    fn api_url_production_returns_prod_url() {
        assert_eq!(ApiEnv::Production.api_url(), PROD_API_URL);
    }
}
