// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! `VeyraFold`: guarded segmented account prefixes feed the complete reference payment checks.
//! All results stay private; the caller replays serially on any speculative failure.

use std::{collections::BTreeMap, sync::OnceLock};

use codec::CanonicalEncode;
use state::{StateAbsenceProof, StateError, StateProof, StateSnapshot, account_key, read_account};
use transaction::{Payment, ValidationContext};
use types::{AccountState, Address, Hash256, StateKey, Transaction, TransactionLane};

use crate::{
    ExecutionError, ExecutionPolicy, PaymentSession, TransactionOutput, payment_resources,
};

const MAX_TRANSACTIONS: usize = 8192;
const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
const SEGMENT_EVENTS: usize = 128;

/// Partial translation of a u64 balance. Composition retains every intermediate guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Guard {
    delta: i128,
    low: i128,
    high: i128,
}

impl Guard {
    const IDENTITY: Self = Self {
        delta: 0,
        low: 0,
        high: u64::MAX as i128,
    };

    fn then(self, next: Self) -> Result<Self, ExecutionError> {
        let result = Self {
            delta: self
                .delta
                .checked_add(next.delta)
                .ok_or(ExecutionError::Conflict)?,
            low: self.low.max(
                next.low
                    .checked_sub(self.delta)
                    .ok_or(ExecutionError::Conflict)?,
            ),
            high: self.high.min(
                next.high
                    .checked_sub(self.delta)
                    .ok_or(ExecutionError::Conflict)?,
            ),
        };
        if result.low > result.high {
            return Err(ExecutionError::Conflict);
        }
        Ok(result)
    }

    fn accepts(self, balance: u64) -> bool {
        (self.low..=self.high).contains(&i128::from(balance))
    }
}

struct Event {
    index: usize,
    debit: bool,
    guard: Guard,
}

#[derive(Clone, Copy)]
struct Prefix {
    guard: Guard,
    outgoing: u64,
}

struct Segment<'a> {
    address: Address,
    seed: &'a AccountState,
    events: &'a [Event],
    summary: OnceLock<Prefix>,
    prefix: OnceLock<Prefix>,
}

struct Inputs {
    sender: OnceLock<AccountState>,
    recipient: OnceLock<AccountState>,
}

/// Local reconstructed input; it cannot issue authenticated state proofs.
struct PairView<'a> {
    root: Hash256,
    sender_key: StateKey,
    recipient_key: StateKey,
    inputs: &'a Inputs,
}

impl StateSnapshot for PairView<'_> {
    fn root(&self) -> Hash256 {
        self.root
    }
    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError> {
        let account = if *key == self.sender_key {
            self.inputs.sender.get()
        } else if *key == self.recipient_key {
            self.inputs.recipient.get()
        } else {
            return Err(StateError::StaleSnapshot);
        };
        account
            .map(|a| Some(a.to_bytes()))
            .ok_or(StateError::StaleSnapshot)
    }
    fn prove(&self, _: &StateKey) -> Result<Option<StateProof>, StateError> {
        Err(StateError::StaleSnapshot)
    }
    fn prove_absence(&self, _: &StateKey) -> Result<Option<StateAbsenceProof>, StateError> {
        Err(StateError::StaleSnapshot)
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Summarize,
    Reconstruct,
    Execute,
}

pub(crate) type FoldResult =
    Result<(Vec<TransactionOutput>, Option<state::CommitSeals>), ExecutionError>;

/// None means unsupported or too small: ordinary DAG execution remains available.
pub(crate) fn speculate(
    parent: &dyn StateSnapshot,
    transactions: &[Transaction],
    context: ValidationContext,
    policy: ExecutionPolicy,
    workers: usize,
    sealing: bool,
) -> Option<FoldResult> {
    if !(64..=MAX_TRANSACTIONS).contains(&transactions.len())
        || transactions
            .iter()
            .any(|tx| tx.lane != TransactionLane::Payments)
    {
        return None;
    }
    let bytes = transactions.iter().try_fold(0usize, |sum, tx| {
        sum.checked_add(transaction::estimate_encoded_len(tx))
            .filter(|n| *n <= MAX_INPUT_BYTES)
    });
    bytes?;
    let payments = transactions
        .iter()
        .map(|tx| Payment::decode(&tx.payload))
        .collect::<Result<Vec<_>, _>>();
    let payments = match payments {
        Ok(p) => p,
        Err(e) => return Some(Err(e.into())),
    };
    if transactions
        .iter()
        .zip(&payments)
        .any(|(tx, p)| tx.sender == p.recipient)
    {
        return None;
    }
    let mut accounts = BTreeMap::new();
    for (tx, payment) in transactions.iter().zip(&payments) {
        for address in [tx.sender, payment.recipient] {
            if let std::collections::btree_map::Entry::Vacant(slot) = accounts.entry(address) {
                match read_account(parent, address) {
                    Ok(Some(account)) => {
                        slot.insert((account, Vec::new()));
                    }
                    Ok(None) => return None,
                    Err(e) => return Some(Err(e.into())),
                }
            }
        }
    }
    let seals = if sealing && accounts.len() >= 512 {
        let writes: Vec<_> = transactions
            .iter()
            .zip(&payments)
            .map(|(tx, payment)| vec![account_key(tx.sender), account_key(payment.recipient)])
            .collect();
        let ids: Vec<_> = transactions
            .iter()
            .map(transaction::compute_tx_id)
            .collect();
        parent.plan_seals(crypto::compute_transactions_root(&ids), &writes)
    } else {
        None
    };
    Some(
        run(
            parent,
            transactions,
            &payments,
            context,
            policy,
            workers,
            accounts,
            seals.as_ref(),
        )
        .map(|outputs| (outputs, seals)),
    )
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)] // Three phases share one retained pool and immutable plan.
fn run(
    parent: &dyn StateSnapshot,
    transactions: &[Transaction],
    payments: &[Payment],
    context: ValidationContext,
    policy: ExecutionPolicy,
    workers: usize,
    mut accounts: BTreeMap<Address, (AccountState, Vec<Event>)>,
    seals: Option<&state::CommitSeals>,
) -> Result<Vec<TransactionOutput>, ExecutionError> {
    for (index, (tx, payment)) in transactions.iter().zip(payments).enumerate() {
        let resources = payment_resources(tx)?;
        if !resources.fits_in(tx.resource_limit) {
            return Err(ExecutionError::ResourceLimit);
        }
        let fee = resources
            .checked_cost(policy.prices)
            .ok_or(ExecutionError::ResourceLimit)?;
        let debit = payment
            .amount
            .checked_add(fee)
            .ok_or(ExecutionError::Conflict)?;
        let reserve = tx
            .resource_limit
            .checked_cost(policy.prices)
            .and_then(|cost| cost.checked_add(payment.amount))
            .ok_or(ExecutionError::Conflict)?;
        accounts
            .get_mut(&tx.sender)
            .ok_or(ExecutionError::Conflict)?
            .1
            .push(Event {
                index,
                debit: true,
                guard: Guard {
                    delta: -i128::from(debit),
                    low: i128::from(reserve),
                    high: i128::from(u64::MAX),
                },
            });
        accounts
            .get_mut(&payment.recipient)
            .ok_or(ExecutionError::Conflict)?
            .1
            .push(Event {
                index,
                debit: false,
                guard: Guard {
                    delta: i128::from(payment.amount),
                    low: 0,
                    high: i128::from(u64::MAX - payment.amount),
                },
            });
    }
    let segments: Vec<_> = accounts
        .iter()
        .flat_map(|(&address, (seed, events))| {
            events.chunks(SEGMENT_EVENTS).map(move |events| Segment {
                address,
                seed,
                events,
                summary: OnceLock::new(),
                prefix: OnceLock::new(),
            })
        })
        .collect();
    let inputs: Vec<_> = (0..transactions.len())
        .map(|_| Inputs {
            sender: OnceLock::new(),
            recipient: OnceLock::new(),
        })
        .collect();
    // The same bounded workers serve summaries, reconstructed inputs and strict
    // reference execution. No locks or per-transaction dependency messages.
    let task = |(phase, range): (Phase, std::ops::Range<usize>)| {
        let mut outputs = Vec::new();
        for index in range {
            match phase {
                Phase::Summarize => {
                    let segment = &segments[index];
                    let mut summary = Prefix {
                        guard: Guard::IDENTITY,
                        outgoing: 0,
                    };
                    for event in segment.events {
                        summary.guard = summary.guard.then(event.guard)?;
                        summary.outgoing += u64::from(event.debit);
                    }
                    segment
                        .summary
                        .set(summary)
                        .map_err(|_| ExecutionError::Conflict)?;
                }
                Phase::Reconstruct => {
                    let segment = &segments[index];
                    let prefix = segment.prefix.get().ok_or(ExecutionError::Conflict)?;
                    let mut balance = i128::from(segment.seed.balance)
                        .checked_add(prefix.guard.delta)
                        .ok_or(ExecutionError::Conflict)?;
                    let mut nonce = segment
                        .seed
                        .nonce
                        .checked_add(prefix.outgoing)
                        .ok_or(ExecutionError::Conflict)?;
                    for event in segment.events {
                        let account = AccountState {
                            nonce,
                            balance: u64::try_from(balance)
                                .map_err(|_| ExecutionError::Conflict)?,
                        };
                        let slot = if event.debit {
                            &inputs[event.index].sender
                        } else {
                            &inputs[event.index].recipient
                        };
                        slot.set(account).map_err(|_| ExecutionError::Conflict)?;
                        balance = balance
                            .checked_add(event.guard.delta)
                            .ok_or(ExecutionError::Conflict)?;
                        nonce = nonce
                            .checked_add(u64::from(event.debit))
                            .ok_or(ExecutionError::Conflict)?;
                    }
                }
                Phase::Execute => {
                    let tx = &transactions[index];
                    let view = PairView {
                        root: parent.root(),
                        sender_key: account_key(tx.sender),
                        recipient_key: account_key(payments[index].recipient),
                        inputs: &inputs[index],
                    };
                    // Complete existing checks, strict signatures, exact receipts,
                    // diffs and observed leases. No duplicate validation rules.
                    let output = PaymentSession::new(&view, context, policy.capacity)
                        .with_prices(policy.prices)
                        .execute(tx)?;
                    if let Some(seals) = seals {
                        seals.record(index, &output.diff)?;
                    }
                    outputs.push(output);
                }
            }
        }
        Ok(outputs)
    };
    std::thread::scope(|scope| {
        let size = workers.min(transactions.len());
        let mut pool = crate::worker_pool::ScopedWorkerPool::new(scope, size, &task)?;
        let ranges = |count: usize, phase| {
            (0..count)
                .step_by(count.div_ceil(size))
                .map(move |start| (phase, start..(start + count.div_ceil(size)).min(count)))
                .collect::<Vec<_>>()
        };
        let mut results = Vec::new();
        pool.map_into(
            ranges(segments.len(), Phase::Summarize).into_iter(),
            &mut results,
        )?;
        let mut address = None;
        let mut prefix = Prefix {
            guard: Guard::IDENTITY,
            outgoing: 0,
        };
        for segment in &segments {
            if address != Some(segment.address) {
                prefix = Prefix {
                    guard: Guard::IDENTITY,
                    outgoing: 0,
                };
                address = Some(segment.address);
            }
            segment
                .prefix
                .set(prefix)
                .map_err(|_| ExecutionError::Conflict)?;
            let summary = segment.summary.get().ok_or(ExecutionError::Conflict)?;
            prefix.guard = prefix.guard.then(summary.guard)?;
            prefix.outgoing = prefix
                .outgoing
                .checked_add(summary.outgoing)
                .ok_or(ExecutionError::Conflict)?;
            if !prefix.guard.accepts(segment.seed.balance)
                || segment.seed.nonce.checked_add(prefix.outgoing).is_none()
            {
                return Err(ExecutionError::Conflict);
            }
        }
        pool.map_into(
            ranges(segments.len(), Phase::Reconstruct).into_iter(),
            &mut results,
        )?;
        pool.map_into(
            ranges(transactions.len(), Phase::Execute).into_iter(),
            &mut results,
        )?;
        Ok(results.into_iter().flatten().collect())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_translation_matches_all_intermediate_balances() {
        // Exhaustive small model, including impossible prefixes and later funding.
        for a in -4i128..=4 {
            for b in -4i128..=4 {
                for c in -4i128..=4 {
                    let guard = |d: i128| Guard {
                        delta: d,
                        low: 0.max(-d),
                        high: 12.min(12 - d),
                    };
                    let left = guard(a).then(guard(b)).and_then(|g| g.then(guard(c)));
                    let right = guard(b).then(guard(c)).and_then(|g| guard(a).then(g));
                    assert_eq!(left, right);
                    for balance in 0..=12u64 {
                        let mut value = i128::from(balance);
                        let valid = [a, b, c].into_iter().all(|d| {
                            value += d;
                            (0..=12).contains(&value)
                        });
                        assert_eq!(left.as_ref().is_ok_and(|g| g.accepts(balance)), valid);
                    }
                }
            }
        }
    }
}
