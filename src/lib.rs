//! Types and helpers for building a symbolized-coredump JSON blob.
//!
//! The blob is what `cgcl` posts to the codegraph web front-end via a URL
//! fragment: base64-encoded (URL-safe, no padding) gzipped JSON. Keeping it in
//! the fragment means the payload never hits the server's logs; using gzip
//! lets the browser decode it with the native `DecompressionStream` API
//! without shipping a decoder.

pub mod dpkg;
pub mod gdb;

use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Current schema version. Bump when adding fields the server needs to notice.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_name: Option<String>,
    pub frames: Vec<Frame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codename: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// Path to the loaded binary (executable or shared library).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    /// GNU build-id of the binary (hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    /// Binary Debian package that ships `binary`, from `dpkg -S`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
    /// Source package name (from `dpkg-query -W -f='${Source}'`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
    /// Optional path to the source file relative to the source package root, if
    /// the client was able to resolve it. When absent the server falls back to
    /// the (usually absolute) `file` path and searches for a matching leaf.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_rel_path: Option<String>,
}

impl Report {
    pub fn new() -> Self {
        Report {
            version: SCHEMA_VERSION,
            created_at: chrono::Utc::now(),
            hostname: None,
            kernel: None,
            os: None,
            executable: None,
            command_line: None,
            signal: None,
            signal_name: None,
            frames: Vec::new(),
        }
    }

    /// Encode as URL-safe base64 of gzip(JSON), suitable for placing in a URL
    /// fragment. The fragment form is `#v=1&d=<encoded>`.
    pub fn encode(&self) -> Result<String> {
        use std::io::Write;
        let json = serde_json::to_vec(self).context("serialise report")?;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&json).context("gzip compress")?;
        let compressed = enc.finish().context("gzip finish")?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(compressed))
    }

    pub fn decode(encoded: &str) -> Result<Self> {
        use std::io::Read;
        let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .context("base64 decode")?;
        let mut dec = flate2::read::GzDecoder::new(&compressed[..]);
        let mut json = Vec::new();
        dec.read_to_end(&mut json).context("gzip decompress")?;
        serde_json::from_slice(&json).context("parse report JSON")
    }
}

impl Default for Report {
    fn default() -> Self {
        Report::new()
    }
}

/// Build a full URL for the codegraph symbolize view. `base` is typically
/// `https://codegraph.jelmer.uk`.
pub fn symbolize_url(base: &str, report: &Report) -> Result<String> {
    let encoded = report.encode()?;
    let base = base.trim_end_matches('/');
    Ok(format!("{base}/+symbolize#v={SCHEMA_VERSION}&d={encoded}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut r = Report::new();
        r.executable = Some("/usr/bin/foo".into());
        r.signal = Some(11);
        r.signal_name = Some("SIGSEGV".into());
        r.frames.push(Frame {
            index: 0,
            address: Some("0xdead".into()),
            function: Some("crash".into()),
            file: Some("src/foo.rs".into()),
            line: Some(42),
            column: None,
            binary: Some("/usr/bin/foo".into()),
            build_id: Some("abcd".into()),
            package: Some("foo".into()),
            package_version: Some("1.2-1".into()),
            source_package: Some("foo".into()),
            source_version: Some("1.2-1".into()),
            source_rel_path: None,
        });
        let encoded = r.encode().unwrap();
        let back = Report::decode(&encoded).unwrap();
        assert_eq!(back.frames.len(), 1);
        assert_eq!(back.frames[0].function.as_deref(), Some("crash"));
        assert_eq!(back.signal, Some(11));
        // The encoded blob rides in a URL fragment, so it must not contain
        // characters that would truncate or split it: `+`, `/`, `=` from
        // standard base64, and `#`/`&` which delimit fragment key-value pairs.
        for bad in ['+', '/', '=', '#', '&'] {
            assert!(
                !encoded.contains(bad),
                "encoded payload contains {bad:?}: {encoded}",
            );
        }
    }

    #[test]
    fn url_shape() {
        let r = Report::new();
        let u = symbolize_url("https://codegraph.jelmer.uk/", &r).unwrap();
        assert!(u.starts_with("https://codegraph.jelmer.uk/+symbolize#v=1&d="));
    }
}
