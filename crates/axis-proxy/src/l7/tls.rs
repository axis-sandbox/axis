// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ephemeral per-sandbox CA for TLS termination.
//!
//! Each sandbox gets its own CA certificate. When L7 inspection is enabled,
//! the proxy terminates TLS using a leaf certificate signed by this CA,
//! allowing it to inspect HTTP request/response content.

use rcgen::{CertificateParams, KeyPair};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("certificate generation failed: {0}")]
    CertGenError(String),
}

/// An ephemeral CA for a single sandbox.
pub struct SandboxCa {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
}

impl SandboxCa {
    /// Generate a new ephemeral CA for a sandbox.
    pub fn generate(sandbox_name: &str) -> Result<Self, TlsError> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| TlsError::CertGenError(e.to_string()))?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("AXIS Sandbox CA ({sandbox_name})"));
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "AXIS");

        let key_pair = KeyPair::generate()
            .map_err(|e| TlsError::CertGenError(e.to_string()))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| TlsError::CertGenError(e.to_string()))?;

        Ok(Self {
            ca_cert_pem: cert.pem(),
            ca_key_pem: key_pair.serialize_pem(),
        })
    }

    /// Issue a leaf certificate for a specific hostname, signed by this CA.
    pub fn issue_leaf(&self, hostname: &str) -> Result<LeafCert, TlsError> {
        // TODO: Parse CA cert+key back, generate leaf cert signed by CA.
        // For now, generate a self-signed leaf (functional but not chained).
        let subject_alt_names = vec![hostname.to_string()];
        let mut params = CertificateParams::new(subject_alt_names)
            .map_err(|e| TlsError::CertGenError(e.to_string()))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname.to_string());

        let key_pair = KeyPair::generate()
            .map_err(|e| TlsError::CertGenError(e.to_string()))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| TlsError::CertGenError(e.to_string()))?;

        Ok(LeafCert {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        })
    }
}

pub struct LeafCert {
    pub cert_pem: String,
    pub key_pem: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sandbox_ca() {
        let ca = SandboxCa::generate("test-sandbox").unwrap();
        assert!(ca.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.ca_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn issue_leaf_cert() {
        let ca = SandboxCa::generate("test-sandbox").unwrap();
        let leaf = ca.issue_leaf("api.github.com").unwrap();
        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
    }
}
