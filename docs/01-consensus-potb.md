<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 1. PoTB Consensus and Fast Finality

## 1.1 Separation of responsibilities

PoTB determines effective validator weight. Weighted VRF sampling uses that weight to select a committee and producer. BFT finality fixes one transaction order. The execution engine separately verifies the resulting state transition.

These responsibilities MUST remain separate interfaces. A faster executor cannot gain consensus weight, a producer cannot commit unverified adaptive measurements, and the consensus state machine must not depend on worker scheduling.

## 1.2 PoTB weight

Each epoch derives an effective non-negative fixed-point weight from finalized evidence:

```text
effective_weight = policy(time_score, behavior_score, trust_score, penalties, caps)
```

Exact scoring constants remain subject to simulation, calibration, governance rules, and independent security review. Weight computation MUST use checked integer or specified fixed-point arithmetic. A tie MUST be resolved by canonical validator identity bytes.

PoTB is an anti-Sybil heuristic, not a proof that coordinated ownership is impossible. Time, trust graphs, network diversity, and correlation analysis can all be manipulated. Documentation and user interfaces MUST not claim otherwise.

## 1.3 Weighted VRF committee selection

For each height, eligible validators evaluate a VRF over a domain-separated input containing at least:

```text
chain_id || epoch || height || parent_finality_randomness || role
```

A proof is valid only when it verifies under the registered validator key and exact protocol domain. Eligibility probability is proportional to effective PoTB weight. Selection MUST:

1. verify every VRF proof;
2. reject zero-weight, banned, duplicate, and ineligible identities;
3. rank eligible outputs with a specified weighted transformation using integer arithmetic;
4. use canonical identity bytes as the final tie-breaker;
5. select without replacement;
6. commit the selected committee and weights in consensus data.

The final mathematical sampler and VRF suite are not chosen by this baseline. They require test vectors and bias analysis before implementation is called complete.

## 1.4 Partial rotation

The active committee persists across heights. At each height, a deterministic replacement count is computed from the configured rotation ratio, initially approximately 10%. Retained members preserve continuity; replacement seats come from current weighted VRF results.

Safety rules:

- rotation is computed from finalized parent state only;
- no identity occupies more than one seat;
- the outgoing committee finalizes the transition to the next committee;
- committee roots are included in proposal and vote signing bytes;
- parameter changes activate only at an epoch boundary after finalization.

Ten percent is a starting target, not a production constant. Tests must evaluate churn, overlap safety, liveness, and adversarial weight concentration.

## 1.5 Producer selection and pipelining

The producer is selected from the active committee with a separately domain-separated VRF role. While height `h` is voting, eligible producers may prepare height `h + 1` using the latest safe snapshot and mempool view. Preparation is speculative: it MUST be discarded or replayed if the finalized parent, capacity, committee, or transaction order differs.

No proposal for `h + 1` becomes vote-eligible before `h` is finalized. Pipelining saves preparation time; it does not relax height ordering.

## 1.6 Fast BFT finality

Each height may contain multiple timeout-driven rounds. A round has:

1. **proposal** — the designated producer publishes an ordered block proposal;
2. **prevote** — members vote for a valid proposal or nil;
3. **precommit** — members lock after observing a prevote quorum and vote for the locked block or nil;
4. **finalize** — a valid precommit certificate makes the block irreversible.

A quorum is voting power strictly greater than two thirds:

```text
quorum(total) = floor(2 * total / 3) + 1
```

Votes bind chain, height, round, phase, block hash or nil, and committee root. A node MUST persist anti-equivocation decisions before transmitting a proposal, prevote, or precommit. Two different signed values for the same identity, height, round, and phase form slashable evidence.

Lock, unlock, timeout, and certificate rules need a dedicated normative state-machine specification before production implementation.

## 1.7 Consensus/execution decoupling

Consensus validates proposal structure, availability, transaction identities, declared resource bounds, and ordering. It need not wait for all local execution optimizations before exchanging votes, but a node MUST NOT finalize or commit a state root it cannot verify.

The proposal commits:

- ordered transaction root;
- parent state root;
- expected post-state and receipt roots;
- resource usage and active capacity;
- active committee root.

Execution operates against an immutable parent snapshot and produces receipts plus state diffs. The commit stage publishes diffs only after the BFT certificate and execution commitments both validate.

## 1.8 Pipeline

Stages overlap across heights:

```text
height h:     propagation -> prevote -> precommit -> execution check -> commit
height h + 1:              prepare/reconstruct -> speculative execution
height h + 2:                                   transaction prefetch
```

Implementations may overlap execution earlier when safe. The externally visible rule remains simple: transaction order comes from consensus, execution results come from deterministic validation, and canonical state changes only in the commit stage.

## 1.9 Safety assumptions and open work

The baseline does not prove PoTB anti-domination, sampler fairness, BFT safety under rotating weighted committees, or liveness under partial synchrony. Required work includes formal modeling, adversarial simulation, VRF selection analysis, persistent anti-double-sign testing, timeout calibration, and independent review.
