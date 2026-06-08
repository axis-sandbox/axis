// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Credential placeholder resolution and injection.
//!
//! Rewrites HTTP request headers/query parameters to inject real credentials
//! from host-side environment variables or a secure store. The sandbox process
//! never receives the actual credential values.

use axis_core::policy::{InferenceRoute, Policy};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("unresolved placeholder: {0}")]
    Unresolved(String),

    #[error("environment variable not found: {0}")]
    EnvNotFound(String),

    #[error("unsupported placeholder: {0}")]
    UnsupportedPlaceholder(String),

    #[error("invalid credential injection route '{route}': {reason}")]
    InvalidRoute { route: String, reason: String },

    #[error("invalid HTTP request for credential injection: {0}")]
    InvalidHttpRequest(String),
}

/// Resolves credential placeholders in HTTP headers.
#[derive(Clone, Default)]
pub struct SecretResolver {
    /// Static secret mappings (name → value).
    secrets: HashMap<String, String>,
}

impl SecretResolver {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    /// Add a static secret.
    pub fn add_secret(&mut self, name: String, value: String) {
        self.secrets.insert(name, value);
    }

    /// Resolve a placeholder string.
    ///
    /// Supported formats:
    /// - `axis:resolve:env:VAR_NAME` — resolve from environment variable
    /// - `axis:resolve:secret:NAME` — resolve from static secret store
    pub fn resolve(&self, placeholder: &str) -> Result<String, SecretError> {
        if let Some(var_name) = placeholder.strip_prefix("axis:resolve:env:") {
            std::env::var(var_name).map_err(|_| SecretError::EnvNotFound(var_name.into()))
        } else if let Some(secret_name) = placeholder.strip_prefix("axis:resolve:secret:") {
            self.secrets
                .get(secret_name)
                .cloned()
                .ok_or_else(|| SecretError::Unresolved(secret_name.into()))
        } else if placeholder.starts_with("axis:resolve:") {
            Err(SecretError::UnsupportedPlaceholder(placeholder.to_string()))
        } else {
            // Not a placeholder — return as-is.
            Ok(placeholder.to_string())
        }
    }

    /// Scan a header value for placeholders and resolve them.
    pub fn resolve_header_value(&self, value: &str) -> Result<String, SecretError> {
        if value.starts_with("axis:resolve:") {
            self.resolve(value)
        } else {
            Ok(value.to_string())
        }
    }
}

#[derive(Clone)]
pub struct CredentialInjector {
    rules: Vec<CredentialRule>,
    resolver: SecretResolver,
}

#[derive(Clone)]
struct CredentialRule {
    host: String,
    port: Option<u16>,
    scheme: Option<EndpointScheme>,
    path_prefix: Option<String>,
    requires_inference_pattern: bool,
    header: Option<HeaderInjection>,
    query: Vec<QueryInjection>,
}

#[derive(Clone)]
struct HeaderInjection {
    name: String,
    value: HeaderValue,
}

#[derive(Clone)]
enum HeaderValue {
    BearerEnv { env_name: String },
    RawEnv { env_name: String },
}

#[derive(Clone)]
struct QueryInjection {
    name: String,
    placeholder: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EndpointScheme {
    Http,
    Https,
}

struct ParsedHttpHead {
    method: String,
    uri: String,
    version: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl CredentialInjector {
    pub fn from_policy(policy: &Policy) -> Result<Self, SecretError> {
        let resolver = SecretResolver::new();
        let mut rules = Vec::new();
        for route in &policy.inference.routes {
            if let Some(rule) = CredentialRule::from_route(route, &resolver)? {
                rules.push(rule);
            }
        }
        Ok(Self { rules, resolver })
    }

    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }

    pub fn connection_requires_injection(&self, host: &str, port: u16, is_tls: bool) -> bool {
        let host = normalize_host(host);
        self.rules
            .iter()
            .any(|rule| rule.matches_connection(&host, port, is_tls))
    }

    pub fn rewrite_http_request_head(
        &self,
        connect_host: &str,
        connect_port: u16,
        is_tls: bool,
        head: &[u8],
    ) -> Result<Option<Vec<u8>>, SecretError> {
        let host = normalize_host(connect_host);
        let rules: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.matches_connection(&host, connect_port, is_tls))
            .collect();
        if rules.is_empty() {
            return Ok(None);
        }

        let parsed = ParsedHttpHead::parse(head)?;
        let Some(rule) = rules
            .into_iter()
            .find(|rule| rule.applies_to(&parsed, &host))
        else {
            return Ok(None);
        };

        Ok(Some(rule.rewrite(&parsed, &self.resolver)?))
    }
}

impl CredentialRule {
    fn from_route(
        route: &InferenceRoute,
        resolver: &SecretResolver,
    ) -> Result<Option<Self>, SecretError> {
        let raw_endpoint = route.endpoint.as_deref();
        let endpoint = raw_endpoint.and_then(parse_endpoint);
        if let Some(raw_endpoint) = raw_endpoint
            && endpoint.is_none()
            && (route.api_key_env.is_some() || raw_endpoint.contains("axis:resolve:"))
        {
            return Err(SecretError::InvalidRoute {
                route: route.name.clone(),
                reason: "credential routes require an http:// or https:// endpoint".into(),
            });
        }
        let query = endpoint
            .as_ref()
            .map(|endpoint| query_injections(route, endpoint.query.as_deref(), resolver))
            .transpose()?
            .unwrap_or_default();
        let header = route
            .api_key_env
            .as_deref()
            .map(|env_name| header_injection(route, env_name))
            .transpose()?;

        if header.is_none() && query.is_empty() {
            return Ok(None);
        }

        let host = endpoint
            .as_ref()
            .map(|endpoint| endpoint.host.clone())
            .or_else(|| route.provider.as_deref().and_then(provider_host).map(str::to_string))
            .ok_or_else(|| SecretError::InvalidRoute {
                route: route.name.clone(),
                reason: "api_key_env or endpoint placeholders require an endpoint host or known provider".into(),
            })?;
        let host = normalize_host(&host);
        let scheme = endpoint
            .as_ref()
            .map(|endpoint| endpoint.scheme)
            .or_else(|| {
                route
                    .provider
                    .as_deref()
                    .and_then(provider_host)
                    .map(|_| EndpointScheme::Https)
            });
        let port = endpoint
            .as_ref()
            .and_then(|endpoint| endpoint.port)
            .or_else(|| scheme.map(default_port_for_scheme));
        let path_prefix = endpoint
            .as_ref()
            .and_then(|endpoint| non_root_path_prefix(&endpoint.path));
        let requires_inference_pattern =
            requires_inference_pattern(route.provider.as_deref(), &host);

        Ok(Some(Self {
            host,
            port,
            scheme,
            path_prefix,
            requires_inference_pattern,
            header,
            query,
        }))
    }

    fn matches_connection(&self, host: &str, port: u16, is_tls: bool) -> bool {
        if self.host != host {
            return false;
        }
        if let Some(rule_port) = self.port
            && rule_port != port
        {
            return false;
        }
        if let Some(scheme) = self.scheme
            && scheme.is_tls() != is_tls
        {
            return false;
        }
        true
    }

    fn applies_to(&self, request: &ParsedHttpHead, host: &str) -> bool {
        if let Some(prefix) = &self.path_prefix {
            if path_has_dot_segment(&request.path) {
                return false;
            }
            if !path_matches_prefix(&request.path, prefix) {
                return false;
            }
        }
        if !self.requires_inference_pattern {
            return true;
        }
        crate::l7::inference::detect_inference_pattern(&request.method, &request.path, host)
            .is_some()
    }

    fn rewrite(
        &self,
        request: &ParsedHttpHead,
        resolver: &SecretResolver,
    ) -> Result<Vec<u8>, SecretError> {
        let header = self
            .header
            .as_ref()
            .map(|header| header.resolve(resolver))
            .transpose()?;

        let mut query_values = Vec::new();
        for query in &self.query {
            let value = resolver.resolve(&query.placeholder)?;
            query_values.push((query.name.as_str(), value));
        }

        let uri = rewrite_uri_query(&request.uri, &query_values);
        let mut out = Vec::new();
        out.extend_from_slice(
            format!("{} {} {}\r\n", request.method, uri, request.version).as_bytes(),
        );

        for (name, value) in &request.headers {
            if let Some((inject_name, _)) = &header
                && name.eq_ignore_ascii_case(inject_name)
            {
                continue;
            }
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }

        if let Some((name, value)) = header {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        Ok(out)
    }
}

impl HeaderInjection {
    fn resolve(&self, resolver: &SecretResolver) -> Result<(String, String), SecretError> {
        let value = match &self.value {
            HeaderValue::BearerEnv { env_name } => {
                let secret = resolver.resolve(&format!("axis:resolve:env:{env_name}"))?;
                format!("Bearer {secret}")
            }
            HeaderValue::RawEnv { env_name } => {
                resolver.resolve(&format!("axis:resolve:env:{env_name}"))?
            }
        };
        Ok((self.name.clone(), value))
    }
}

impl ParsedHttpHead {
    fn parse(head: &[u8]) -> Result<Self, SecretError> {
        let text = std::str::from_utf8(head)
            .map_err(|_| SecretError::InvalidHttpRequest("request head is not UTF-8".into()))?;
        let mut lines = text.lines();
        let request_line = lines
            .next()
            .ok_or_else(|| SecretError::InvalidHttpRequest("missing request line".into()))?;
        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| SecretError::InvalidHttpRequest("missing method".into()))?;
        let uri = parts
            .next()
            .ok_or_else(|| SecretError::InvalidHttpRequest("missing URI".into()))?;
        let version = parts
            .next()
            .ok_or_else(|| SecretError::InvalidHttpRequest("missing HTTP version".into()))?;

        let path = uri_path(uri);
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').ok_or_else(|| {
                SecretError::InvalidHttpRequest(
                    "malformed header in route-scoped request".to_string(),
                )
            })?;
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }

        Ok(Self {
            method: method.to_string(),
            uri: uri.to_string(),
            version: version.to_string(),
            path,
            headers,
        })
    }
}

struct EndpointParts {
    scheme: EndpointScheme,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
}

fn header_injection(
    route: &InferenceRoute,
    env_name: &str,
) -> Result<HeaderInjection, SecretError> {
    validate_env_name(route, env_name)?;
    let provider = route.provider.as_deref().map(str::to_ascii_lowercase);
    if provider.as_deref() == Some("anthropic") {
        Ok(HeaderInjection {
            name: "x-api-key".into(),
            value: HeaderValue::RawEnv {
                env_name: env_name.into(),
            },
        })
    } else {
        Ok(HeaderInjection {
            name: "Authorization".into(),
            value: HeaderValue::BearerEnv {
                env_name: env_name.into(),
            },
        })
    }
}

fn validate_env_name(route: &InferenceRoute, env_name: &str) -> Result<(), SecretError> {
    let valid = !env_name.is_empty()
        && env_name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(SecretError::InvalidRoute {
            route: route.name.clone(),
            reason: format!(
                "api_key_env must be a non-empty uppercase environment variable name: {env_name}"
            ),
        })
    }
}

fn query_injections(
    route: &InferenceRoute,
    query: Option<&str>,
    resolver: &SecretResolver,
) -> Result<Vec<QueryInjection>, SecretError> {
    let Some(query) = query else {
        return Ok(Vec::new());
    };
    let mut injections = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if value.starts_with("axis:resolve:") {
            if let Some(env_name) = value.strip_prefix("axis:resolve:env:") {
                validate_env_name(route, env_name)?;
            }
            resolver
                .resolve(value)
                .map(|_| ())
                .or_else(|err| match err {
                    SecretError::EnvNotFound(_) | SecretError::Unresolved(_) => Ok(()),
                    other => Err(other),
                })?;
            injections.push(QueryInjection {
                name: name.to_string(),
                placeholder: value.to_string(),
            });
        }
    }
    if injections.iter().any(|query| query.name.is_empty()) {
        return Err(SecretError::InvalidRoute {
            route: route.name.clone(),
            reason: "query placeholder name must not be empty".into(),
        });
    }
    Ok(injections)
}

fn parse_endpoint(endpoint: &str) -> Option<EndpointParts> {
    let (scheme, after_scheme) = endpoint.split_once("://").and_then(|(scheme, rest)| {
        Some((
            match scheme.to_ascii_lowercase().as_str() {
                "http" => EndpointScheme::Http,
                "https" => EndpointScheme::Https,
                _ => return None,
            },
            rest,
        ))
    })?;
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = after_scheme[..authority_end].rsplit('@').next()?.trim();
    if authority.is_empty() {
        return None;
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        let port = if suffix.is_empty() {
            None
        } else if let Some(port) = suffix.strip_prefix(':') {
            Some(port.parse::<u16>().ok()?)
        } else {
            return None;
        };
        (host.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() || port.is_empty() {
            return None;
        }
        (host.to_string(), Some(port.parse::<u16>().ok()?))
    } else {
        (authority.to_string(), Some(default_port_for_scheme(scheme)))
    };
    if host.is_empty() {
        return None;
    }
    let path_and_more = &after_scheme[authority_end..];
    let path = path_and_more
        .find(['?', '#'])
        .map(|idx| &path_and_more[..idx])
        .unwrap_or(path_and_more);

    let query = endpoint
        .split_once('?')
        .map(|(_, query)| query.split('#').next().unwrap_or(query).to_string())
        .filter(|query| !query.is_empty());

    Some(EndpointParts {
        scheme,
        host: normalize_host(&host),
        port,
        path: if path.is_empty() {
            "/".into()
        } else {
            path.into()
        },
        query,
    })
}

fn provider_host(provider: &str) -> Option<&'static str> {
    match provider.to_ascii_lowercase().as_str() {
        "openai" => Some("api.openai.com"),
        "anthropic" => Some("api.anthropic.com"),
        _ => None,
    }
}

fn requires_inference_pattern(provider: Option<&str>, host: &str) -> bool {
    provider
        .map(|provider| {
            matches!(
                provider.to_ascii_lowercase().as_str(),
                "openai" | "anthropic"
            )
        })
        .unwrap_or(false)
        || matches!(
            host,
            "api.openai.com" | "api.anthropic.com" | "inference.local"
        )
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_matches('[')
        .trim_matches(']')
        .to_ascii_lowercase()
}

impl EndpointScheme {
    fn is_tls(self) -> bool {
        matches!(self, Self::Https)
    }
}

fn default_port_for_scheme(scheme: EndpointScheme) -> u16 {
    match scheme {
        EndpointScheme::Http => 80,
        EndpointScheme::Https => 443,
    }
}

fn non_root_path_prefix(path: &str) -> Option<String> {
    let path = path.trim();
    if path.is_empty() || path == "/" {
        None
    } else {
        Some(path.to_string())
    }
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix.ends_with('/') {
        path.starts_with(prefix)
    } else {
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

fn path_has_dot_segment(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment == "." || segment == "..")
}

fn uri_path(uri: &str) -> String {
    let without_scheme = uri
        .split_once("://")
        .map(|(_, rest)| rest.find('/').map(|idx| &rest[idx..]).unwrap_or("/"))
        .unwrap_or(uri);
    without_scheme
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(without_scheme)
        .to_string()
}

fn rewrite_uri_query(uri: &str, query_values: &[(&str, String)]) -> String {
    if query_values.is_empty() {
        return uri.to_string();
    }

    let (without_fragment, fragment) = uri.split_once('#').unwrap_or((uri, ""));
    let (base, query) = without_fragment
        .split_once('?')
        .map(|(base, query)| (base, Some(query)))
        .unwrap_or((without_fragment, None));
    let mut pairs: Vec<String> = query
        .map(|query| {
            query
                .split('&')
                .filter(|pair| {
                    let name = pair.split_once('=').map(|(name, _)| name).unwrap_or(*pair);
                    !query_values
                        .iter()
                        .any(|(inject_name, _)| name.eq_ignore_ascii_case(inject_name))
                })
                .filter(|pair| !pair.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    for (name, value) in query_values {
        pairs.push(format!("{name}={}", percent_encode_query_value(value)));
    }

    let mut rewritten = format!("{base}?{}", pairs.join("&"));
    if !fragment.is_empty() {
        rewritten.push('#');
        rewritten.push_str(fragment);
    }
    rewritten
}

fn percent_encode_query_value(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn policy(yaml: &str) -> Policy {
        Policy::from_yaml(yaml).unwrap()
    }

    #[test]
    fn resolve_env_placeholder() {
        let _lock = ENV_LOCK.lock().unwrap();
        // Set a test env var.
        unsafe {
            std::env::set_var("AXIS_TEST_KEY", "test-value-12345");
        }
        let resolver = SecretResolver::new();
        let val = resolver.resolve("axis:resolve:env:AXIS_TEST_KEY").unwrap();
        assert_eq!(val, "test-value-12345");
        unsafe {
            std::env::remove_var("AXIS_TEST_KEY");
        }
    }

    #[test]
    fn resolve_static_secret() {
        let mut resolver = SecretResolver::new();
        resolver.add_secret("my-api-key".into(), "secret-value".into());
        let val = resolver.resolve("axis:resolve:secret:my-api-key").unwrap();
        assert_eq!(val, "secret-value");
    }

    #[test]
    fn passthrough_non_placeholder() {
        let resolver = SecretResolver::new();
        let val = resolver.resolve("just-a-normal-value").unwrap();
        assert_eq!(val, "just-a-normal-value");
    }

    #[test]
    fn error_on_missing_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let resolver = SecretResolver::new();
        unsafe {
            std::env::remove_var("NONEXISTENT_VAR_12345");
        }
        let err = resolver
            .resolve("axis:resolve:env:NONEXISTENT_VAR_12345")
            .unwrap_err();
        assert!(matches!(err, SecretError::EnvNotFound(_)));
    }

    #[test]
    fn unsupported_placeholder_fails_closed() {
        let resolver = SecretResolver::new();
        let err = resolver
            .resolve("axis:resolve:file:/tmp/provider-key")
            .unwrap_err();
        assert!(matches!(err, SecretError::UnsupportedPlaceholder(_)));
    }

    #[test]
    fn api_key_env_injects_authorization_for_matching_inference_host() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_PROVIDER_KEY", "provider-secret");
        }
        let policy = policy(
            r#"
version: 1
name: inject-auth
inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_PROVIDER_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        let rewritten = injector
            .rewrite_http_request_head(
                "inference.local",
                80,
                false,
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local\r\nAuthorization: Bearer sandbox-placeholder\r\n\r\n",
            )
            .unwrap()
            .unwrap();
        let rewritten = String::from_utf8(rewritten).unwrap();

        assert!(rewritten.contains("Authorization: Bearer provider-secret\r\n"));
        assert!(!rewritten.contains("sandbox-placeholder"));
        unsafe {
            std::env::remove_var("AXIS_TEST_PROVIDER_KEY");
        }
    }

    #[test]
    fn api_key_env_does_not_inject_for_unmatched_host_or_path() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_OPENAI_KEY", "openai-secret");
        }
        let policy = policy(
            r#"
version: 1
name: inject-only-openai
inference:
  routes:
    - name: openai
      provider: openai
      api_key_env: AXIS_TEST_OPENAI_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        assert!(
            injector
                .rewrite_http_request_head(
                    "example.com",
                    443,
                    true,
                    b"POST /v1/chat/completions HTTP/1.1\r\nHost: example.com\r\n\r\n",
                )
                .unwrap()
                .is_none()
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "api.openai.com",
                    443,
                    true,
                    b"GET /not-an-inference-route HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
                )
                .unwrap()
                .is_none()
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "api.openai.com",
                    443,
                    true,
                    b"POST /v1/chat/completions-extra HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
                )
                .unwrap()
                .is_none()
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "api.openai.com",
                    443,
                    true,
                    b"POST /v1/chat/completions/../files HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
                )
                .unwrap()
                .is_none()
        );
        unsafe {
            std::env::remove_var("AXIS_TEST_OPENAI_KEY");
        }
    }

    #[test]
    fn unresolved_api_key_env_fails_closed_without_secret_value() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("AXIS_TEST_MISSING_KEY");
        }
        let policy = policy(
            r#"
version: 1
name: missing-key
inference:
  routes:
    - name: mock-provider
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_MISSING_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        let err = injector
            .rewrite_http_request_head(
                "inference.local",
                80,
                false,
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: inference.local\r\n\r\n",
            )
            .unwrap_err();

        assert!(
            matches!(err, SecretError::EnvNotFound(ref name) if name == "AXIS_TEST_MISSING_KEY")
        );
        assert!(!err.to_string().contains("provider-secret"));
    }

    #[test]
    fn endpoint_query_placeholder_rewrites_query_value() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_QUERY_KEY", "query secret+value");
        }
        let policy = policy(
            r#"
version: 1
name: inject-query
inference:
  routes:
    - name: query-provider
      endpoint: "http://provider.example/v1?api_key=axis:resolve:env:AXIS_TEST_QUERY_KEY"
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        let rewritten = injector
            .rewrite_http_request_head(
                "provider.example",
                80,
                false,
                b"GET /v1/models?limit=10&api_key=sandbox-value HTTP/1.1\r\nHost: provider.example\r\n\r\n",
            )
            .unwrap()
            .unwrap();
        let rewritten = String::from_utf8(rewritten).unwrap();

        assert!(
            rewritten
                .starts_with("GET /v1/models?limit=10&api_key=query%20secret%2Bvalue HTTP/1.1\r\n")
        );
        assert!(!rewritten.contains("sandbox-value"));
        unsafe {
            std::env::remove_var("AXIS_TEST_QUERY_KEY");
        }
    }

    #[test]
    fn endpoint_injection_respects_scheme_port_and_path_prefix() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_SCOPED_KEY", "scoped-secret");
        }
        let policy = policy(
            r#"
version: 1
name: scoped-route
inference:
  routes:
    - name: scoped
      endpoint: "https://provider.example:9443/v1/chat"
      api_key_env: AXIS_TEST_SCOPED_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        assert!(
            injector
                .rewrite_http_request_head(
                    "provider.example",
                    9443,
                    false,
                    b"POST /v1/chat HTTP/1.1\r\nHost: provider.example\r\n\r\n",
                )
                .unwrap()
                .is_none(),
            "HTTPS route must not inject into plaintext traffic"
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "provider.example",
                    443,
                    true,
                    b"POST /v1/chat HTTP/1.1\r\nHost: provider.example\r\n\r\n",
                )
                .unwrap()
                .is_none(),
            "route must not inject on a different port"
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "provider.example",
                    9443,
                    true,
                    b"POST /v2/chat HTTP/1.1\r\nHost: provider.example\r\n\r\n",
                )
                .unwrap()
                .is_none(),
            "route must not inject outside endpoint path prefix"
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "provider.example",
                    9443,
                    true,
                    b"POST /v1/chatty HTTP/1.1\r\nHost: provider.example\r\n\r\n",
                )
                .unwrap()
                .is_none(),
            "route prefix must stop at a path segment boundary"
        );
        assert!(
            injector
                .rewrite_http_request_head(
                    "provider.example",
                    9443,
                    true,
                    b"POST /v1/chat/../models HTTP/1.1\r\nHost: provider.example\r\n\r\n",
                )
                .unwrap()
                .is_none(),
            "dot-segment paths must not be credential-scoped before upstream normalization"
        );

        let rewritten = injector
            .rewrite_http_request_head(
                "provider.example",
                9443,
                true,
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: provider.example\r\n\r\n",
            )
            .unwrap()
            .unwrap();
        let rewritten = String::from_utf8(rewritten).unwrap();
        assert!(rewritten.contains("Authorization: Bearer scoped-secret\r\n"));
        unsafe {
            std::env::remove_var("AXIS_TEST_SCOPED_KEY");
        }
    }

    #[test]
    fn lf_only_http_head_is_rewritten_consistently() {
        let _lock = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("AXIS_TEST_LF_KEY", "lf-secret");
        }
        let policy = policy(
            r#"
version: 1
name: lf-route
inference:
  routes:
    - name: lf
      endpoint: "http://inference.local"
      api_key_env: AXIS_TEST_LF_KEY
"#,
        );
        let injector = CredentialInjector::from_policy(&policy).unwrap();

        let rewritten = injector
            .rewrite_http_request_head(
                "inference.local",
                80,
                false,
                b"POST /v1/chat/completions HTTP/1.1\nHost: inference.local\n\n",
            )
            .unwrap()
            .unwrap();
        let rewritten = String::from_utf8(rewritten).unwrap();

        assert!(rewritten.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
        assert!(rewritten.contains("Authorization: Bearer lf-secret\r\n"));
        unsafe {
            std::env::remove_var("AXIS_TEST_LF_KEY");
        }
    }

    #[test]
    fn unsupported_endpoint_query_placeholder_rejects_policy() {
        let policy = policy(
            r#"
version: 1
name: bad-placeholder
inference:
  routes:
    - name: query-provider
      endpoint: "http://provider.example/v1?api_key=axis:resolve:file:/tmp/key"
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected unsupported placeholder to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::UnsupportedPlaceholder(_)));
    }

    #[test]
    fn unparseable_endpoint_with_placeholder_rejects_policy() {
        let policy = policy(
            r#"
version: 1
name: bad-endpoint-placeholder
inference:
  routes:
    - name: query-provider
      endpoint: "provider.example/v1?api_key=axis:resolve:env:AXIS_TEST_QUERY_KEY"
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected unparseable credential endpoint to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::InvalidRoute { .. }));
    }

    #[test]
    fn unparseable_endpoint_with_api_key_env_rejects_policy() {
        let policy = policy(
            r#"
version: 1
name: bad-api-key-endpoint
inference:
  routes:
    - name: provider
      provider: openai
      endpoint: "ftp://api.openai.com/v1"
      api_key_env: OPENAI_API_KEY
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected unparseable credential endpoint to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::InvalidRoute { .. }));
    }

    #[test]
    fn malformed_endpoint_port_with_api_key_env_rejects_policy() {
        let policy = policy(
            r#"
version: 1
name: bad-api-key-port
inference:
  routes:
    - name: provider
      endpoint: "http://provider.example:notaport/v1"
      api_key_env: OPENAI_API_KEY
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected malformed credential endpoint port to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::InvalidRoute { .. }));
    }

    #[test]
    fn invalid_endpoint_query_env_rejects_policy() {
        let policy = policy(
            r#"
version: 1
name: bad-query-env
inference:
  routes:
    - name: query-provider
      endpoint: "http://provider.example/v1?api_key=axis:resolve:env:not-valid"
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected invalid query env placeholder to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::InvalidRoute { .. }));
    }

    #[test]
    fn invalid_api_key_env_rejects_policy() {
        let policy = policy(
            r#"
version: 1
name: bad-env
inference:
  routes:
    - name: query-provider
      endpoint: "http://provider.example"
      api_key_env: "not-valid"
"#,
        );

        let err = match CredentialInjector::from_policy(&policy) {
            Ok(_) => panic!("expected invalid api_key_env to reject policy"),
            Err(err) => err,
        };

        assert!(matches!(err, SecretError::InvalidRoute { .. }));
    }
}
