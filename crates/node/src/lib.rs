// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Node pipeline coordination across propagation, consensus, execution, and commit.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use types::Resources;

/// Default initial capacity for a newly created node.
pub const DEFAULT_CAPACITY: Resources = Resources {
    compute: 1000,
    memory: 1024,
    io: 256,
    bandwidth: 1024,
};

/// Minimum capacity floor — never scale below this.
pub const MIN_CAPACITY: Resources = Resources {
    compute: 1,
    memory: 1,
    io: 1,
    bandwidth: 1,
};

/// Number of observations retained in the rolling window for adaptive sizing.
pub const LATENCY_WINDOW: usize = 16;

/// Overlappable stages for height `h` and `h + 1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineStage {
    /// Receive or reconstruct an ordered proposal.
    Propagation,
    /// Collect prevotes and precommits without mutating canonical state.
    Voting,
    /// Execute the consensus-fixed transaction order on a snapshot.
    Execution,
    /// Publish deferred state changes after execution and finality validation.
    Commit,
}

/// Finalized performance observations used by adaptive block sizing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityObservation {
    /// Measured resources consumed by a finalized block.
    pub used: Resources,
    /// Whether the block met the finality latency target.
    pub within_latency_target: bool,
}

/// Deterministically adjusts block limits from a finalized observation window.
pub trait CapacityController {
    /// Computes the next consensus-visible capacity. Local live measurements may
    /// inform proposals, but only finalized, quantized observations may change it.
    fn next_capacity(&self, current: Resources, observations: &[CapacityObservation]) -> Resources;
}

/// Top-level node service boundary.
pub trait NodeService {
    /// Advances available stages without coupling finality to execution threads.
    fn advance(&mut self) -> Result<(), NodeError>;
}

/// Node orchestration failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeError {
    /// A required subsystem is not ready.
    NotReady,
    /// A finalized commitment disagrees with deterministic execution.
    CommitmentMismatch,
    /// A bounded queue or configured resource ceiling was reached.
    CapacityExceeded,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "required subsystem not ready"),
            Self::CommitmentMismatch => {
                write!(
                    f,
                    "finalized commitment disagrees with deterministic execution"
                )
            }
            Self::CapacityExceeded => {
                write!(
                    f,
                    "bounded queue or configured resource ceiling was reached"
                )
            }
        }
    }
}

impl std::error::Error for NodeError {}

/// Adaptive controller that scales block capacity based on finalized observations.
///
/// Maintains a rolling window of [`CapacityObservation`]s. After the window is
/// full the controller computes the average used resources and scales up (110%)
/// if every class is within target or down (90%) if any class exceeds it, never
/// dropping below [`MIN_CAPACITY`].
#[derive(Clone, Debug)]
pub struct AdaptiveCapacityController {
    #[allow(dead_code)]
    initial: Resources,
    window_size: usize,
}

impl AdaptiveCapacityController {
    /// Creates a new controller with the given initial capacity and window size.
    #[must_use]
    pub fn new(initial: Resources, window_size: usize) -> Self {
        Self {
            initial,
            window_size,
        }
    }

    /// Computes the average used resources across a set of observations.
    fn average_used(observations: &[CapacityObservation]) -> Resources {
        if observations.is_empty() {
            return Resources::ZERO;
        }
        let count = observations.len() as u64;
        let mut sum = Resources::ZERO;
        for obs in observations {
            sum = sum.saturating_add(obs.used);
        }
        Resources {
            compute: sum.compute / count,
            memory: sum.memory / count,
            io: sum.io / count,
            bandwidth: sum.bandwidth / count,
        }
    }

    /// Scales a resource value by the given percentage using checked integer math.
    ///
    /// `percent` is expressed as hundredths (e.g. 110 = 110%). The result is
    /// `(value * percent) / 100`, floored to at least `floor` or clamped on
    /// overflow.
    fn scale(value: u64, percent: u64, floor: u64) -> u64 {
        value
            .checked_mul(percent)
            .map_or(u64::MAX, |v| v / 100)
            .max(floor)
    }
}

impl CapacityController for AdaptiveCapacityController {
    fn next_capacity(&self, current: Resources, observations: &[CapacityObservation]) -> Resources {
        let usable = if observations.len() > self.window_size {
            &observations[observations.len() - self.window_size..]
        } else {
            observations
        };

        if usable.is_empty() {
            return current;
        }

        let avg = Self::average_used(usable);

        let scale_up = avg.fits_in(current);

        if scale_up {
            Resources {
                compute: Self::scale(current.compute, 110, MIN_CAPACITY.compute),
                memory: Self::scale(current.memory, 110, MIN_CAPACITY.memory),
                io: Self::scale(current.io, 110, MIN_CAPACITY.io),
                bandwidth: Self::scale(current.bandwidth, 110, MIN_CAPACITY.bandwidth),
            }
        } else {
            Resources {
                compute: Self::scale(current.compute, 90, MIN_CAPACITY.compute),
                memory: Self::scale(current.memory, 90, MIN_CAPACITY.memory),
                io: Self::scale(current.io, 90, MIN_CAPACITY.io),
                bandwidth: Self::scale(current.bandwidth, 90, MIN_CAPACITY.bandwidth),
            }
        }
    }
}

/// Current high-level state of the node pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeState {
    /// No active block processing.
    Idle,
    /// Synchronizing with the network.
    Syncing,
    /// Participating in consensus voting.
    Voting {
        /// Block height being voted on.
        height: u64,
        /// Consensus round number.
        round: u32,
    },
    /// Executing a block's transaction order.
    Executing {
        /// Block height being executed.
        height: u64,
    },
    /// Committing finalized state changes.
    Committing {
        /// Block height being committed.
        height: u64,
    },
}

/// Concrete [`NodeService`] implementation that drives the pipeline state machine
/// and records capacity observations for adaptive sizing.
#[derive(Clone, Debug)]
pub struct BasicNodeService {
    /// Current pipeline state.
    pub state: NodeState,
    /// Adaptive capacity controller.
    pub capacity_controller: AdaptiveCapacityController,
    /// Recorded observations from completed blocks.
    pub observations: Vec<CapacityObservation>,
}

impl BasicNodeService {
    /// Creates a new service with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: NodeState::Idle,
            capacity_controller: AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW),
            observations: Vec::new(),
        }
    }

    /// Returns the current pipeline state.
    #[must_use]
    pub fn current_state(&self) -> &NodeState {
        &self.state
    }

    /// Returns the current adaptive capacity.
    #[must_use]
    pub fn current_capacity(&self) -> Resources {
        self.capacity_controller
            .next_capacity(DEFAULT_CAPACITY, &self.observations)
    }
}

impl Default for BasicNodeService {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeService for BasicNodeService {
    fn advance(&mut self) -> Result<(), NodeError> {
        self.state = match &self.state {
            NodeState::Idle => NodeState::Syncing,
            NodeState::Syncing => NodeState::Voting {
                height: 1,
                round: 0,
            },
            NodeState::Voting { height, .. } => NodeState::Executing { height: *height },
            NodeState::Executing { height } => NodeState::Committing { height: *height },
            NodeState::Committing { height: _ } => {
                self.observations.push(CapacityObservation {
                    used: Resources {
                        compute: 100,
                        memory: 128,
                        io: 32,
                        bandwidth: 64,
                    },
                    within_latency_target: true,
                });
                NodeState::Idle
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_error_display() {
        assert_eq!(
            NodeError::NotReady.to_string(),
            "required subsystem not ready"
        );
        assert_eq!(
            NodeError::CommitmentMismatch.to_string(),
            "finalized commitment disagrees with deterministic execution"
        );
        assert_eq!(
            NodeError::CapacityExceeded.to_string(),
            "bounded queue or configured resource ceiling was reached"
        );
    }

    #[test]
    fn node_error_is_error() {
        let e: &dyn std::error::Error = &NodeError::NotReady;
        assert!(e.source().is_none());
    }

    #[test]
    fn default_capacity_values() {
        assert_eq!(DEFAULT_CAPACITY.compute, 1000);
        assert_eq!(DEFAULT_CAPACITY.memory, 1024);
        assert_eq!(DEFAULT_CAPACITY.io, 256);
        assert_eq!(DEFAULT_CAPACITY.bandwidth, 1024);
    }

    #[test]
    fn min_capacity_values() {
        assert_eq!(MIN_CAPACITY.compute, 1);
        assert_eq!(MIN_CAPACITY.memory, 1);
        assert_eq!(MIN_CAPACITY.io, 1);
        assert_eq!(MIN_CAPACITY.bandwidth, 1);
    }

    #[test]
    fn latency_window_value() {
        assert_eq!(LATENCY_WINDOW, 16);
    }

    // -- AdaptiveCapacityController tests --

    #[test]
    fn controller_returns_current_when_no_observations() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW);
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &[]);
        assert_eq!(result, DEFAULT_CAPACITY);
    }

    #[test]
    fn controller_scales_up_when_within_target() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW);
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 500,
                memory: 512,
                io: 100,
                bandwidth: 500,
            },
            within_latency_target: true,
        }];
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        // 110% scaling
        assert_eq!(result.compute, 1100); // 1000 * 110 / 100
        assert_eq!(result.memory, 1126); // 1024 * 110 / 100
        assert_eq!(result.io, 281); // 256 * 110 / 100
        assert_eq!(result.bandwidth, 1126); // 1024 * 110 / 100
    }

    #[test]
    fn controller_scales_down_when_exceeds() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW);
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 1500,
                memory: 1100,
                io: 300,
                bandwidth: 1100,
            },
            within_latency_target: false,
        }];
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        // 90% scaling
        assert_eq!(result.compute, 900); // 1000 * 90 / 100
        assert_eq!(result.memory, 921); // 1024 * 90 / 100
        assert_eq!(result.io, 230); // 256 * 90 / 100
        assert_eq!(result.bandwidth, 921); // 1024 * 90 / 100
    }

    #[test]
    fn controller_clamps_to_min_capacity() {
        let ctrl = AdaptiveCapacityController::new(
            Resources {
                compute: 10,
                memory: 10,
                io: 10,
                bandwidth: 10,
            },
            LATENCY_WINDOW,
        );
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 100,
                memory: 100,
                io: 100,
                bandwidth: 100,
            },
            within_latency_target: false,
        }];
        let result = ctrl.next_capacity(
            Resources {
                compute: 10,
                memory: 10,
                io: 10,
                bandwidth: 10,
            },
            &obs,
        );
        // 90% of 10 = 9, but min is 1 → stays at 9, repeated scaling eventually hits 1
        assert_eq!(result.compute, 9);
        assert_eq!(result.memory, 9);
        assert_eq!(result.io, 9);
        assert_eq!(result.bandwidth, 9);
    }

    #[test]
    fn controller_clamps_to_min_after_repeated_scaling_down() {
        let ctrl = AdaptiveCapacityController::new(
            Resources {
                compute: 2,
                memory: 2,
                io: 2,
                bandwidth: 2,
            },
            LATENCY_WINDOW,
        );
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 100,
                memory: 100,
                io: 100,
                bandwidth: 100,
            },
            within_latency_target: false,
        }];
        // 90% of 2 = 1 (integer floor), which is MIN_CAPACITY
        let result = ctrl.next_capacity(
            Resources {
                compute: 2,
                memory: 2,
                io: 2,
                bandwidth: 2,
            },
            &obs,
        );
        assert_eq!(result, MIN_CAPACITY);
    }

    #[test]
    fn controller_uses_rolling_window() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, 4);
        let obs = vec![
            CapacityObservation {
                used: Resources {
                    compute: 500,
                    memory: 500,
                    io: 50,
                    bandwidth: 500,
                },
                within_latency_target: true,
            },
            CapacityObservation {
                used: Resources {
                    compute: 500,
                    memory: 500,
                    io: 50,
                    bandwidth: 500,
                },
                within_latency_target: true,
            },
            CapacityObservation {
                used: Resources {
                    compute: 2000,
                    memory: 2000,
                    io: 500,
                    bandwidth: 2000,
                },
                within_latency_target: false,
            },
            CapacityObservation {
                used: Resources {
                    compute: 2000,
                    memory: 2000,
                    io: 500,
                    bandwidth: 2000,
                },
                within_latency_target: false,
            },
        ];
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        // Average: (500+500+2000+2000)/4=1250, (500+500+2000+2000)/4=1250, etc.
        // 1250 > 1000 → scale down
        assert_eq!(result.compute, 900);
    }

    #[test]
    fn controller_ignores_observations_beyond_window() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, 2);
        let mut obs = vec![
            CapacityObservation {
                used: Resources {
                    compute: 2000,
                    memory: 2000,
                    io: 500,
                    bandwidth: 2000,
                },
                within_latency_target: false,
            },
            CapacityObservation {
                used: Resources {
                    compute: 2000,
                    memory: 2000,
                    io: 500,
                    bandwidth: 2000,
                },
                within_latency_target: false,
            },
        ];
        // These should be ignored because window is 2
        obs.push(CapacityObservation {
            used: Resources {
                compute: 100,
                memory: 100,
                io: 10,
                bandwidth: 100,
            },
            within_latency_target: true,
        });
        obs.push(CapacityObservation {
            used: Resources {
                compute: 100,
                memory: 100,
                io: 10,
                bandwidth: 100,
            },
            within_latency_target: true,
        });
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        // Only last 2 obs used: avg = (100+100)/2=100, which fits → scale up
        assert_eq!(result.compute, 1100);
    }

    #[test]
    fn controller_scales_up_correctly() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW);
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 100,
                memory: 100,
                io: 100,
                bandwidth: 100,
            },
            within_latency_target: true,
        }];
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        // 110% of each field
        assert_eq!(result.compute, 1100);
        assert_eq!(result.memory, 1126);
        assert_eq!(result.io, 281);
        assert_eq!(result.bandwidth, 1126);
    }

    #[test]
    fn controller_scales_down_correctly() {
        let ctrl = AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW);
        let obs = vec![CapacityObservation {
            used: Resources {
                compute: 1000,
                memory: 1000,
                io: 1000,
                bandwidth: 1000,
            },
            within_latency_target: false,
        }];
        let result = ctrl.next_capacity(DEFAULT_CAPACITY, &obs);
        // 90% of each field
        assert_eq!(result.compute, 900);
        assert_eq!(result.memory, 921);
        assert_eq!(result.io, 230);
        assert_eq!(result.bandwidth, 921);
    }

    // -- NodeState tests --

    #[test]
    fn node_state_clone_and_eq() {
        let s1 = NodeState::Voting {
            height: 10,
            round: 2,
        };
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    #[test]
    fn node_state_debug() {
        let s = NodeState::Executing { height: 42 };
        let debug = format!("{s:?}");
        assert!(debug.contains("Executing"));
        assert!(debug.contains("42"));
    }

    // -- BasicNodeService tests --

    #[test]
    fn service_starts_idle() {
        let svc = BasicNodeService::new();
        assert_eq!(*svc.current_state(), NodeState::Idle);
    }

    #[test]
    fn service_default_capacity() {
        let svc = BasicNodeService::new();
        assert_eq!(svc.current_capacity(), DEFAULT_CAPACITY);
    }

    #[test]
    fn service_transitions_through_pipeline() {
        let mut svc = BasicNodeService::new();
        assert_eq!(*svc.current_state(), NodeState::Idle);

        svc.advance().unwrap();
        assert_eq!(*svc.current_state(), NodeState::Syncing);

        svc.advance().unwrap();
        assert!(matches!(
            *svc.current_state(),
            NodeState::Voting {
                height: 1,
                round: 0
            }
        ));

        svc.advance().unwrap();
        assert_eq!(*svc.current_state(), NodeState::Executing { height: 1 });

        svc.advance().unwrap();
        assert_eq!(*svc.current_state(), NodeState::Committing { height: 1 });

        svc.advance().unwrap();
        assert_eq!(*svc.current_state(), NodeState::Idle);
    }

    #[test]
    fn service_records_observation_on_commit() {
        let mut svc = BasicNodeService::new();
        // Walk through one full cycle
        for _ in 0..5 {
            svc.advance().unwrap();
        }
        assert_eq!(svc.observations.len(), 1);
        assert!(svc.observations[0].within_latency_target);
    }

    #[test]
    fn service_capacity_updates_with_observations() {
        let mut svc = BasicNodeService::new();
        // Multiple cycles to accumulate observations
        for _ in 0..20 {
            svc.advance().unwrap();
        }
        assert!(!svc.observations.is_empty());
        // After enough observations the capacity should differ from default
        let cap = svc.current_capacity();
        // Default obs: compute=100 < 1000 → scale up
        assert!(cap.compute >= DEFAULT_CAPACITY.compute);
    }

    #[test]
    fn service_multiple_full_cycles() {
        let mut svc = BasicNodeService::new();
        for cycle in 0..3 {
            for _ in 0..5 {
                svc.advance().unwrap();
            }
            assert_eq!(*svc.current_state(), NodeState::Idle);
            assert_eq!(svc.observations.len(), cycle + 1);
        }
    }

    #[test]
    fn service_default_trait() {
        let svc = BasicNodeService::default();
        assert_eq!(*svc.current_state(), NodeState::Idle);
    }

    #[test]
    fn service_observation_recording() {
        let mut svc = BasicNodeService::new();
        assert!(svc.observations.is_empty());
        // One cycle
        for _ in 0..5 {
            svc.advance().unwrap();
        }
        assert_eq!(svc.observations.len(), 1);
        let obs = svc.observations[0];
        assert_eq!(
            obs.used,
            Resources {
                compute: 100,
                memory: 128,
                io: 32,
                bandwidth: 64,
            }
        );
        assert!(obs.within_latency_target);
    }
}
