// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HTTP request/response parsing for L7 policy evaluation.

/// Parsed HTTP request for policy evaluation.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub content_type: Option<String>,
}

/// Parse an HTTP request line and headers into a ParsedRequest.
pub fn parse_request_head(head: &[u8]) -> Option<ParsedRequest> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.lines();

    let request_line = lines.next()?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let method = parts[0].to_string();
    let uri = parts[1];

    let (path, query) = if let Some((p, q)) = uri.split_once('?') {
        (p.to_string(), Some(q.to_string()))
    } else {
        (uri.to_string(), None)
    };

    let mut content_type = None;
    for line in lines {
        if let Some(val) = line.strip_prefix("Content-Type: ") {
            content_type = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("content-type: ") {
            content_type = Some(val.trim().to_string());
        }
    }

    Some(ParsedRequest {
        method,
        path,
        query,
        content_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_get_request() {
        let head = b"GET /v1/models?limit=10 HTTP/1.1\r\nHost: inference.local\r\n\r\n";
        let req = parse_request_head(head).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/v1/models");
        assert_eq!(req.query.as_deref(), Some("limit=10"));
    }

    #[test]
    fn parse_post_request_with_content_type() {
        let head = b"POST /v1/chat/completions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n";
        let req = parse_request_head(head).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/v1/chat/completions");
        assert_eq!(req.content_type.as_deref(), Some("application/json"));
    }
}
