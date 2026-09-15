// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Local-only observability that cannot influence consensus results.

#![forbid(unsafe_code)]

/// A bounded local metric sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metric {
    /// Stable metric identifier.
    pub name: &'static str,
    /// Integer value; floating point stays outside protocol-adjacent APIs.
    pub value: u64,
}

/// Receives local metrics without feeding protocol decisions.
pub trait TelemetrySink: Send + Sync {
    /// Records a best-effort sample.
    fn record(&self, metric: Metric);
}

/// Sink used when telemetry is disabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopTelemetry;

impl TelemetrySink for NoopTelemetry {
    fn record(&self, _metric: Metric) {}
}
