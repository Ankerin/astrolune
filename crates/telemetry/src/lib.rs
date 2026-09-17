// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Local-only observability that cannot influence consensus results.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Mutex;

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

/// In-memory telemetry sink that retains a bounded history of values per metric.
pub struct InMemoryTelemetry {
    max_history: usize,
    inner: Mutex<Inner>,
}

struct Inner {
    map: BTreeMap<&'static str, Vec<u64>>,
    total: usize,
}

impl InMemoryTelemetry {
    /// Creates a new sink with the given per-metric capacity.
    #[must_use]
    pub fn new(max_history: usize) -> Self {
        Self {
            max_history,
            inner: Mutex::new(Inner {
                map: BTreeMap::new(),
                total: 0,
            }),
        }
    }

    /// Returns the recorded values for `name` in chronological order.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn values(&self, name: &str) -> Vec<u64> {
        let inner = self.inner.lock().expect("telemetry lock poisoned");
        inner.map.get(name).cloned().unwrap_or_default()
    }

    /// Returns the most recently recorded value for `name`, if any.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn latest(&self, name: &str) -> Option<u64> {
        let inner = self.inner.lock().expect("telemetry lock poisoned");
        inner.map.get(name).and_then(|v| v.last().copied())
    }

    /// Returns how many values have been recorded for `name`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn count(&self, name: &str) -> usize {
        let inner = self.inner.lock().expect("telemetry lock poisoned");
        inner.map.get(name).map_or(0, Vec::len)
    }

    /// Clears all recorded history.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().expect("telemetry lock poisoned");
        inner.map.clear();
        inner.total = 0;
    }

    /// Returns the total number of values recorded across all metric names.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn total_count(&self) -> usize {
        let inner = self.inner.lock().expect("telemetry lock poisoned");
        inner.total
    }
}

impl TelemetrySink for InMemoryTelemetry {
    fn record(&self, metric: Metric) {
        let mut inner = self.inner.lock().expect("telemetry lock poisoned");
        inner.total += 1;
        let entry = inner.map.entry(metric.name).or_default();
        if entry.len() >= self.max_history {
            entry.remove(0);
        }
        entry.push(metric.value);
    }
}

/// A monotonically-increasing counter tied to a single metric name.
pub struct Counter {
    name: &'static str,
    value: u64,
}

impl Counter {
    /// Creates a new counter for the given metric name, starting at zero.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self { name, value: 0 }
    }

    /// Increments the counter by one and records the new value into the sink.
    pub fn inc(&mut self, sink: &dyn TelemetrySink) {
        self.value += 1;
        sink.record(Metric {
            name: self.name,
            value: self.value,
        });
    }

    /// Returns the current counter value.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Returns the metric name associated with this counter.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_retrieve() {
        let tel = InMemoryTelemetry::new(8);
        tel.record(Metric {
            name: "latency",
            value: 10,
        });
        tel.record(Metric {
            name: "latency",
            value: 20,
        });
        tel.record(Metric {
            name: "latency",
            value: 30,
        });

        assert_eq!(tel.values("latency"), vec![10, 20, 30]);
        assert_eq!(tel.latest("latency"), Some(30));
        assert_eq!(tel.count("latency"), 3);

        assert!(tel.values("missing").is_empty());
        assert_eq!(tel.latest("missing"), None);
        assert_eq!(tel.count("missing"), 0);
    }

    #[test]
    fn capacity_eviction() {
        let tel = InMemoryTelemetry::new(3);
        for i in 0..6 {
            tel.record(Metric {
                name: "packets",
                value: i,
            });
        }

        assert_eq!(tel.values("packets"), vec![3, 4, 5]);
        assert_eq!(tel.latest("packets"), Some(5));
        assert_eq!(tel.count("packets"), 3);
    }

    #[test]
    fn reset_clears_everything() {
        let tel = InMemoryTelemetry::new(4);
        tel.record(Metric {
            name: "a",
            value: 1,
        });
        tel.record(Metric {
            name: "b",
            value: 2,
        });

        assert_eq!(tel.total_count(), 2);

        tel.reset();

        assert_eq!(tel.total_count(), 0);
        assert!(tel.values("a").is_empty());
        assert!(tel.values("b").is_empty());
    }

    #[test]
    fn counter_increment() {
        let tel = InMemoryTelemetry::new(64);
        let mut counter = Counter::new("requests");

        assert_eq!(counter.value(), 0);

        counter.inc(&tel);
        counter.inc(&tel);
        counter.inc(&tel);

        assert_eq!(counter.value(), 3);
        assert_eq!(tel.latest("requests"), Some(3));
        assert_eq!(tel.count("requests"), 3);
    }

    #[test]
    fn counter_with_noop_sink() {
        let noop = NoopTelemetry;
        let mut counter = Counter::new("noop_metric");

        counter.inc(&noop);
        counter.inc(&noop);

        assert_eq!(counter.value(), 2);
    }

    #[test]
    fn noop_sink_is_truly_noop() {
        let noop = NoopTelemetry;
        noop.record(Metric {
            name: "x",
            value: 1,
        });
        noop.record(Metric {
            name: "x",
            value: 2,
        });
        noop.record(Metric {
            name: "y",
            value: 99,
        });
    }

    #[test]
    fn total_count_across_names() {
        let tel = InMemoryTelemetry::new(16);
        tel.record(Metric {
            name: "a",
            value: 1,
        });
        tel.record(Metric {
            name: "b",
            value: 2,
        });
        tel.record(Metric {
            name: "a",
            value: 3,
        });
        tel.record(Metric {
            name: "c",
            value: 4,
        });
        tel.record(Metric {
            name: "b",
            value: 5,
        });

        assert_eq!(tel.total_count(), 5);
    }

    #[test]
    fn capacity_one_eviction() {
        let tel = InMemoryTelemetry::new(1);
        tel.record(Metric {
            name: "s",
            value: 10,
        });
        assert_eq!(tel.values("s"), vec![10]);

        tel.record(Metric {
            name: "s",
            value: 20,
        });
        assert_eq!(tel.values("s"), vec![20]);

        tel.record(Metric {
            name: "s",
            value: 30,
        });
        assert_eq!(tel.values("s"), vec![30]);
        assert_eq!(tel.count("s"), 1);
    }
}
