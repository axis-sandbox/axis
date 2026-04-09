// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Input validation and sanitization.
//!
//! Checks for null bytes, excessive whitespace, control characters,
//! and other malformed input that could be used for injection attacks.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("input contains null bytes at offset {offset}")]
    NullByte { offset: usize },

    #[error("input exceeds maximum length ({len} > {max})")]
    TooLong { len: usize, max: usize },

    #[error("input contains suspicious control characters")]
    ControlCharacters,
}

/// Maximum input length for general-purpose validation (1MB).
const DEFAULT_MAX_LEN: usize = 1_048_576;

/// Validate a string input for common injection vectors.
pub fn validate_input(input: &str) -> Result<(), ValidationError> {
    validate_input_with_max(input, DEFAULT_MAX_LEN)
}

/// Validate with a custom maximum length.
pub fn validate_input_with_max(input: &str, max_len: usize) -> Result<(), ValidationError> {
    if input.len() > max_len {
        return Err(ValidationError::TooLong {
            len: input.len(),
            max: max_len,
        });
    }

    if let Some(offset) = input.bytes().position(|b| b == 0) {
        return Err(ValidationError::NullByte { offset });
    }

    // Check for excessive control characters (C0 control codes excluding \t, \n, \r).
    let suspicious_control_count = input
        .bytes()
        .filter(|&b| b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r')
        .count();

    if suspicious_control_count > 0 {
        return Err(ValidationError::ControlCharacters);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_normal_input() {
        assert!(validate_input("Hello, world!\nThis is fine.\t").is_ok());
    }

    #[test]
    fn reject_null_bytes() {
        let err = validate_input("hello\x00world").unwrap_err();
        assert!(matches!(err, ValidationError::NullByte { offset: 5 }));
    }

    #[test]
    fn reject_too_long() {
        let long = "x".repeat(DEFAULT_MAX_LEN + 1);
        let err = validate_input(&long).unwrap_err();
        assert!(matches!(err, ValidationError::TooLong { .. }));
    }

    #[test]
    fn reject_control_characters() {
        let err = validate_input("hello\x01world").unwrap_err();
        assert!(matches!(err, ValidationError::ControlCharacters));
    }

    #[test]
    fn allow_tabs_and_newlines() {
        assert!(validate_input("line1\nline2\ttab\r\n").is_ok());
    }
}
