// Copyright 2026 Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Environment variable classification for sandbox launches.

/// Environment variables needed for ordinary process startup and developer
/// tooling inside the sandbox.
pub fn is_essential_sandbox_env_key(key: &str) -> bool {
    matches!(
        normalized_key(key).as_str(),
        "HOME"
            | "USER"
            | "PATH"
            | "LANG"
            | "TERM"
            | "SHELL"
            | "TMPDIR"
            | "XDG_RUNTIME_DIR"
            | "XDG_CONFIG_HOME"
            | "XDG_DATA_HOME"
            | "XDG_CACHE_HOME"
            | "SYSTEMROOT"
            | "SYSTEMDRIVE"
            | "WINDIR"
            | "TEMP"
            | "TMP"
            | "USERPROFILE"
            | "APPDATA"
            | "LOCALAPPDATA"
            | "PROGRAMDATA"
            | "PROGRAMFILES"
            | "PROGRAMFILES(X86)"
            | "COMPUTERNAME"
            | "USERNAME"
            | "NUMBER_OF_PROCESSORS"
            | "PROCESSOR_ARCHITECTURE"
            | "PATHEXT"
            | "COMSPEC"
            | "OS"
            | "HOMEDRIVE"
            | "HOMEPATH"
    )
}

/// Provider configuration that is useful to keep but is not itself a secret.
pub fn is_provider_config_env_key(key: &str) -> bool {
    let key = normalized_key(key);
    (key.starts_with("ANTHROPIC_") || key.starts_with("OPENAI_") || key.starts_with("CLAUDE_"))
        && !is_secret_env_key(&key)
}

/// Proxy variables are controlled by AXIS on Linux; inherited variants can
/// bypass routing expectations or carry credentials in proxy URLs.
pub fn is_proxy_env_key(key: &str) -> bool {
    matches!(
        normalized_key(key).as_str(),
        "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "FTP_PROXY" | "NO_PROXY"
    )
}

/// Conservative classifier for raw credentials that must not cross the Linux
/// sandbox boundary by default.
pub fn is_secret_env_key(key: &str) -> bool {
    let key = normalized_key(key);
    let secret_markers = [
        "API_KEY",
        "ACCESS_KEY",
        "AUTH",
        "BEARER",
        "CLIENT_SECRET",
        "CONNECTION_STRING",
        "CREDENTIAL",
        "ENCRYPTION_KEY",
        "HMAC",
        "ID_TOKEN",
        "JWT",
        "KEYFILE",
        "KEY_FILE",
        "OAUTH",
        "PASSWORD",
        "PASSWD",
        "PRIVATE_KEY",
        "SAS_TOKEN",
        "REFRESH_TOKEN",
        "SECRET",
        "SERVICE_ACCOUNT",
        "SIGNING_KEY",
        "SESSION_TOKEN",
        "STORAGE_KEY",
        "TOKEN",
    ];
    secret_markers.iter().any(|marker| key.contains(marker))
}

/// Host environment keys collected by the CLI/daemon before platform launch.
pub fn is_collected_sandbox_env_key(key: &str) -> bool {
    (is_essential_sandbox_env_key(key) || is_provider_config_env_key(key))
        && !is_secret_env_key(key)
        && !is_proxy_env_key(key)
}

/// Final Linux boundary filter. It intentionally preserves non-secret custom
/// environment variables supplied by existing APIs while stripping credentials
/// and inherited proxy settings.
pub fn retain_linux_sandbox_env(env: &mut Vec<(String, String)>) {
    env.retain(|(key, _)| !is_secret_env_key(key) && !is_proxy_env_key(key));
}

fn normalized_key(key: &str) -> String {
    key.to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_secrets_are_not_collected() {
        for key in [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "AZURE_STORAGE_KEY",
            "AZURE_STORAGE_CONNECTION_STRING",
            "GOOGLE_SERVICE_ACCOUNT_KEY",
        ] {
            assert!(is_secret_env_key(key), "{key}");
            assert!(!is_collected_sandbox_env_key(key), "{key}");
        }
    }

    #[test]
    fn non_secret_provider_config_is_collected() {
        for key in [
            "ANTHROPIC_BASE_URL",
            "OPENAI_ORG_ID",
            "CLAUDE_CODE_ENTRYPOINT",
        ] {
            assert!(!is_secret_env_key(key), "{key}");
            assert!(is_collected_sandbox_env_key(key), "{key}");
        }
    }

    #[test]
    fn proxy_keys_are_case_insensitive_and_not_collected() {
        for key in [
            "HTTP_PROXY",
            "https_proxy",
            "All_Proxy",
            "ftp_proxy",
            "no_proxy",
        ] {
            assert!(is_proxy_env_key(key), "{key}");
            assert!(!is_collected_sandbox_env_key(key), "{key}");
        }
    }

    #[test]
    fn linux_filter_strips_secrets_and_proxy_but_keeps_custom_config() {
        let mut env = vec![
            ("PATH".into(), "/bin".into()),
            ("ANTHROPIC_API_KEY".into(), "secret".into()),
            ("AZURE_STORAGE_CONNECTION_STRING".into(), "secret".into()),
            ("CUSTOM_CONFIG".into(), "value".into()),
            ("All_Proxy".into(), "http://proxy-with-creds".into()),
        ];

        retain_linux_sandbox_env(&mut env);

        assert_eq!(
            env,
            vec![
                ("PATH".into(), "/bin".into()),
                ("CUSTOM_CONFIG".into(), "value".into())
            ]
        );
    }
}
