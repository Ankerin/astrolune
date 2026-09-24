// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Fixed-membership reference network with durable voting and certified catch-up.

use crate::network_wire::{
    MAX_EXCHANGE_BYTES, MAX_TRANSACTION_BYTES, NetworkMessage, SyncRequest, decode_exchange,
    encode_block, encode_exchange,
};
use crate::{
    BlockProducer, ProducerConfig, ProducerError, RoundRobinValidator, SignedBlockProposal,
    TimeoutEvent, ValidatorError,
};
use consensus::{
    AuthenticatedCommittee, Committee, CommitteeMember, LocalBft, LocalBftError, PotbWeight,
    PrevoteCertificate, Vote, VotePhase, VotingStep,
};
use keystore::{DurableSigner, KeystoreError, Signer};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use storage::ChainStorage;
use types::{Block, Hash256, Transaction, ValidatorId};

/// The reference driver deliberately bounds membership and retains a fixed committee.
pub const MAX_NETWORK_VALIDATORS: usize = 32;

/// Shared authenticated recovery state for voting and non-voting network nodes.
pub(crate) struct RecoveredNetwork {
    pub(crate) storage: ChainStorage,
    pub(crate) producer: BlockProducer,
}

/// Distinguishes untrusted peer input from local durability failures that must stop signing.
#[derive(Debug)]
pub enum NetworkNodeError {
    /// Malformed, stale, unauthenticated, or incompatible input.
    Input(String),
    /// Local storage/signing failure; the daemon must stop and recover.
    Local(String),
}
impl std::fmt::Display for NetworkNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input(message) | Self::Local(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for NetworkNodeError {}
impl From<ProducerError> for NetworkNodeError {
    fn from(error: ProducerError) -> Self {
        if matches!(error, ProducerError::Storage(_)) {
            Self::Local(error.to_string())
        } else {
            Self::Input(error.to_string())
        }
    }
}
impl From<ValidatorError> for NetworkNodeError {
    fn from(error: ValidatorError) -> Self {
        match error {
            ValidatorError::Production(error) => error.into(),
            ValidatorError::Voting(LocalBftError::Signing(error))
                if error != KeystoreError::ConflictingSign =>
            {
                Self::Local(error.to_string())
            }
            ValidatorError::Voting(_) => Self::Input(error.to_string()),
        }
    }
}
pub(crate) fn input(error: impl std::fmt::Display) -> NetworkNodeError {
    NetworkNodeError::Input(error.to_string())
}
pub(crate) fn local(error: impl std::fmt::Display) -> NetworkNodeError {
    NetworkNodeError::Local(error.to_string())
}

/// Independently supplied genesis and exact registered keys; peer data cannot change them.
#[derive(Clone)]
pub struct StaticNetwork {
    genesis: genesis::Genesis,
    hash: Hash256,
    keys: Vec<[u8; 32]>,
}
impl StaticNetwork {
    /// Explicitly selects all genesis validators for the fixed round-robin profile.
    pub fn new(genesis: genesis::Genesis, keys: Vec<[u8; 32]>) -> Result<Self, NetworkNodeError> {
        let hash = genesis.commitment().map_err(input)?;
        if genesis.committee_size != genesis.validators.len() || keys.len() > MAX_NETWORK_VALIDATORS
        {
            return Err(input(
                "reference network requires the complete genesis committee, at most 32 validators",
            ));
        }
        let result = Self {
            genesis,
            hash,
            keys,
        };
        result.committee(1)?;
        Ok(result)
    }
    /// Trusted genesis namespace.
    #[must_use]
    pub const fn genesis_hash(&self) -> Hash256 {
        self.hash
    }
    /// Chain identifier exposed to RPC clients.
    #[must_use]
    pub const fn chain_id(&self) -> u32 {
        self.genesis.chain_id
    }
    /// Reconstructs a height-bound context from trusted immutable membership.
    pub fn committee(&self, height: u64) -> Result<AuthenticatedCommittee, NetworkNodeError> {
        AuthenticatedCommittee::new(
            self.genesis.chain_id,
            &Committee {
                height,
                members: self
                    .genesis
                    .validators
                    .iter()
                    .map(|member| CommitteeMember {
                        id: member.id,
                        power: PotbWeight(member.weight),
                    })
                    .collect(),
            },
            &self.keys,
        )
        .map_err(input)
    }
    pub(crate) fn recover(&self, directory: &Path) -> Result<RecoveredNetwork, NetworkNodeError> {
        let network = self;
        let initial = network.genesis.materialize().map_err(input)?;
        let mut storage = ChainStorage::open(directory.join("chain.bin")).map_err(local)?;
        if storage.checkpoint().is_none() {
            storage
                .initialize_genesis(network.hash, initial.clone())
                .map_err(local)?;
        }
        let checkpoint = *storage
            .checkpoint()
            .ok_or_else(|| local("missing checkpoint"))?;
        if usize::try_from(checkpoint.height).ok() != Some(storage.block_count()) {
            return Err(input(
                "certified network requires complete history from genesis",
            ));
        }
        if storage.state().get(&genesis::genesis_key()) != Some(network.hash.as_bytes().as_slice())
            || (checkpoint.height == 0
                && (checkpoint.block != network.hash || checkpoint.state_root != initial.root()))
        {
            return Err(input("archive genesis mismatch"));
        }
        let mut parent = network.hash;
        for height in 1..=checkpoint.height {
            let (block, encoded) = storage
                .read_finalized(height)
                .map_err(local)?
                .ok_or_else(|| input("incomplete certified history"))?;
            if block.header.height != height || block.header.parent != parent {
                return Err(input("history does not descend from trusted genesis"));
            }
            let certificate = consensus::FinalityCertificate::decode(&encoded).map_err(input)?;
            network
                .committee(height)?
                .verify_certificate(&certificate, &block.header)
                .map_err(input)?;
            parent = block.header.compute_hash();
        }
        if parent != checkpoint.block {
            return Err(input("history checkpoint mismatch"));
        }
        let producer = BlockProducer::from_checkpoint(
            network.producer_config(),
            Some(checkpoint),
            storage.state().clone(),
        )?;
        Ok(RecoveredNetwork { storage, producer })
    }

    fn producer_config(&self) -> ProducerConfig {
        ProducerConfig {
            chain_id: self.chain_id(),
            block_capacity: self.genesis.capacity,
            max_transaction_bytes: MAX_TRANSACTION_BYTES,
            max_block_transactions: 15,
            ..ProducerConfig::default()
        }
    }
}

/// Network-driven participant. Only durable certificates advance its public checkpoint.
pub struct NetworkNode {
    network: StaticNetwork,
    participant: Option<RoundRobinValidator>,
    storage: ChainStorage,
    voter: ValidatorId,
    proposal: Option<SignedBlockProposal>,
    valid: Option<(Block, PrevoteCertificate)>,
    votes: BTreeMap<(ValidatorId, VotePhase), Vote>,
    cache_path: PathBuf,
    timer: Option<(TimeoutEvent, Instant)>,
    base_timeout: Duration,
    evidence: crate::evidence::EvidenceStore,
}

impl NetworkNode {
    /// Opens a certified archive and protected signer, rejecting demonstration history.
    /// `signer` must already be provisioned explicitly; missing journals are never recreated.
    pub fn open(
        network: StaticNetwork,
        directory: &Path,
        signer: DurableSigner,
        base_timeout: Duration,
    ) -> Result<Self, NetworkNodeError> {
        if base_timeout < Duration::from_millis(100) || base_timeout > Duration::from_secs(60) {
            return Err(input(
                "round timeout must be between 100 and 60000 milliseconds",
            ));
        }
        let RecoveredNetwork { storage, producer } = network.recover(directory)?;
        let checkpoint = *storage
            .checkpoint()
            .ok_or_else(|| local("missing checkpoint"))?;
        let voter = signer.validator_id(&signer.key_handle()).map_err(local)?;
        let local_voter =
            LocalBft::new(network.committee(producer.height())?, signer, network.hash)
                .map_err(local)?;
        let participant = RoundRobinValidator::new(
            producer,
            local_voter,
            network.committee(checkpoint.height + 1)?,
        )?;
        let mut result = Self {
            evidence: crate::evidence::EvidenceStore::open(directory, &network)?,
            network,
            participant: Some(participant),
            storage,
            voter,
            proposal: None,
            valid: None,
            votes: BTreeMap::new(),
            cache_path: directory.join("consensus-cache.bin"),
            timer: None,
            base_timeout,
        };
        result.restore_cache()?;
        Ok(result)
    }

    fn participant(&self) -> &RoundRobinValidator {
        self.participant
            .as_ref()
            .expect("participant available outside height handoff")
    }
    /// Verified local double-vote proofs, durably retained at most once per member.
    /// Their presence does not alter active weights or finalize an economic penalty.
    pub fn evidence(&self) -> impl Iterator<Item = &consensus::DoubleVoteEvidence> {
        self.evidence.records()
    }
    fn participant_mut(&mut self) -> &mut RoundRobinValidator {
        self.participant
            .as_mut()
            .expect("participant available outside height handoff")
    }
    /// Current committed storage view.
    #[must_use]
    pub const fn storage(&self) -> &ChainStorage {
        &self.storage
    }
    /// Current next height and trusted genesis for synchronization.
    #[must_use]
    pub fn request(&self) -> SyncRequest {
        SyncRequest {
            genesis: self.network.hash,
            height: self.participant().producer().height(),
        }
    }
    /// Current round, useful for operator diagnostics and simulations.
    #[must_use]
    pub fn round(&self) -> u32 {
        self.participant().local().round()
    }
    /// Admits a signed transaction for both production and gossip.
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<Hash256, NetworkNodeError> {
        let id = crate::hash_transaction(&tx);
        self.participant_mut().submit_transaction(tx)?;
        Ok(id)
    }

    /// Bounded response. Untrusted requests select a height, never committee or state authority.
    pub fn respond(&self, request: SyncRequest) -> Result<Vec<u8>, NetworkNodeError> {
        if request.genesis != self.network.hash {
            return Err(input("peer genesis mismatch"));
        }
        let messages = if let Some((block, encoded)) =
            self.storage.read_finalized(request.height).map_err(local)?
        {
            vec![NetworkMessage::Finalized {
                block,
                certificate: consensus::FinalityCertificate::decode(&encoded).map_err(local)?,
            }]
        } else if request.height == self.request().height {
            let mut messages = self.consensus_messages();
            let mut size = 0;
            for tx in self.participant().producer().pending_transactions() {
                size += transaction::estimate_encoded_len(&tx);
                if size > 2 * 1024 * 1024 {
                    break;
                }
                messages.push(NetworkMessage::Transaction(tx));
            }
            messages
        } else {
            Vec::new()
        };
        encode_exchange(self.network.hash, &messages).map_err(input)
    }

    fn consensus_messages(&self) -> Vec<NetworkMessage> {
        let mut messages = Vec::new();
        if let Some((block, proof)) = &self.valid {
            messages.push(NetworkMessage::ValidValue {
                block: block.clone(),
                proof: proof.encode(),
            });
        }
        if let Some(proposal) = &self.proposal {
            messages.push(NetworkMessage::Proposal {
                envelope: proposal.envelope.clone(),
                block: proposal.proposal.block.clone(),
                proof: proposal
                    .valid_round
                    .as_ref()
                    .map_or_else(Vec::new, PrevoteCertificate::encode),
            });
        }
        messages.extend(self.votes.values().cloned().map(NetworkMessage::Vote));
        messages
    }

    /// Decodes the complete response, then authenticates messages individually.
    /// Returns the number rejected; local signing/storage errors are never suppressed.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<usize, NetworkNodeError> {
        let messages = decode_exchange(self.network.hash, bytes).map_err(input)?;
        let mut rejected = 0;
        for message in messages {
            match self.receive_message(message) {
                Ok(()) => {}
                Err(NetworkNodeError::Input(_)) => rejected += 1,
                Err(error) => return Err(error),
            }
        }
        Ok(rejected)
    }

    fn receive_message(&mut self, message: NetworkMessage) -> Result<(), NetworkNodeError> {
        match message {
            NetworkMessage::Transaction(tx) => {
                self.submit_transaction(tx)?;
            }
            NetworkMessage::Finalized { block, certificate } => {
                if block.header.height != self.request().height {
                    return Err(input("stale or nonsequential finalized block"));
                }
                self.participant()
                    .local()
                    .committee()
                    .verify_certificate(&certificate, &block.header)
                    .map_err(input)?;
                let proposal = self
                    .participant()
                    .producer()
                    .execute_received_block(block)?;
                let participant = self
                    .participant
                    .as_mut()
                    .ok_or_else(|| local("height handoff incomplete"))?;
                participant.commit_finalized(&proposal, &certificate, &mut self.storage)?;
                self.advance_height()?;
            }
            NetworkMessage::Vote(vote) => {
                self.receive_peer_vote(vote)?;
            }
            NetworkMessage::ValidValue { block, proof } => {
                let proof =
                    PrevoteCertificate::decode(self.participant().local().committee(), &proof)
                        .map_err(input)?;
                if proof.block() != block.header.compute_hash() || proof.round() > self.round() {
                    return Err(input("invalid available-value evidence"));
                }
                if self
                    .valid
                    .as_ref()
                    .is_some_and(|(_, previous)| previous.round() >= proof.round())
                {
                    return Ok(());
                }
                self.participant()
                    .producer()
                    .execute_received_block(block.clone())?;
                self.valid = Some((block, proof));
                self.persist_cache()?;
            }
            NetworkMessage::Proposal {
                envelope,
                block,
                proof,
            } => {
                if self
                    .proposal
                    .as_ref()
                    .is_some_and(|previous| previous.envelope == envelope)
                {
                    return Ok(());
                }
                if self.proposal.is_some() {
                    return Err(input("conflicting proposal in the active round"));
                }
                let proof = if proof.is_empty() {
                    None
                } else {
                    Some(
                        PrevoteCertificate::decode(self.participant().local().committee(), &proof)
                            .map_err(input)?,
                    )
                };
                self.participant()
                    .local()
                    .verify_proposal(
                        self.participant().proposer(),
                        &envelope,
                        &block.header,
                        proof.as_ref(),
                    )
                    .map_err(input)?;
                let proposal = SignedBlockProposal {
                    envelope,
                    proposal: self
                        .participant()
                        .producer()
                        .execute_received_block(block)?,
                    valid_round: proof,
                };
                // Body is durable before reserving a non-nil vote or lock.
                self.proposal = Some(proposal.clone());
                self.persist_cache()?;
                self.accept_available(&proposal)?;
            }
        }
        Ok(())
    }

    fn accept_available(&mut self, proposal: &SignedBlockProposal) -> Result<(), NetworkNodeError> {
        if let Some(certificate) = self.participant().certificate().cloned() {
            if certificate.block == proposal.envelope.block {
                let participant = self
                    .participant
                    .as_mut()
                    .ok_or_else(|| local("missing participant"))?;
                participant.commit_finalized(
                    &proposal.proposal,
                    &certificate,
                    &mut self.storage,
                )?;
                self.advance_height()?;
            }
        } else if self.participant().local().step() == VotingStep::Precommitted {
            self.participant_mut().restore_proposal(proposal)?;
        } else if !self.votes.contains_key(&(self.voter, VotePhase::Prevote)) {
            let vote = self.participant_mut().accept_proposal(proposal)?;
            self.record_local(vote)?;
        } else {
            self.participant_mut().restore_proposal(proposal)?;
        }
        Ok(())
    }

    fn record_local(&mut self, vote: Vote) -> Result<(), NetworkNodeError> {
        self.votes.insert((vote.voter, vote.phase), vote);
        self.persist_cache()
    }

    fn receive_peer_vote(&mut self, vote: Vote) -> Result<(), NetworkNodeError> {
        let key = (vote.voter, vote.phase);
        if self.votes.get(&key) == Some(&vote) {
            return Ok(());
        }
        let result = self.participant_mut().receive_vote(vote.clone());
        if result.is_err() {
            let proofs: Vec<_> = self.participant().evidence().cloned().collect();
            for proof in proofs {
                self.evidence.persist(proof)?;
            }
        }
        result?;
        self.votes.insert(key, vote);
        Ok(())
    }

    /// Drives one bounded unit of work using a monotonic clock. No synthetic votes exist.
    pub fn tick(&mut self, now: Instant) -> Result<(), NetworkNodeError> {
        if let Some(certificate) = self.participant().certificate().cloned()
            && let Some(proposal) = &self.proposal
            && proposal.envelope.block == certificate.block
        {
            let proposal = proposal.proposal.clone();
            let participant = self
                .participant
                .as_mut()
                .ok_or_else(|| local("missing participant"))?;
            participant.commit_finalized(&proposal, &certificate, &mut self.storage)?;
            self.advance_height()?;
            return Ok(());
        }
        if self.participant().certificate().is_some() {
            return Ok(());
        }
        if !self.votes.contains_key(&(self.voter, VotePhase::Prevote))
            && matches!(
                self.participant().local().step(),
                VotingStep::AwaitingProposal | VotingStep::Prevoted
            )
            && let Some(proposal) = self.proposal.clone()
        {
            match self.accept_available(&proposal) {
                Ok(()) | Err(NetworkNodeError::Input(_)) => {}
                Err(error) => return Err(error),
            }
        }
        self.propose_if_designated()?;
        if self.proposal.is_some()
            && !self.votes.contains_key(&(self.voter, VotePhase::Precommit))
            && matches!(
                self.participant().local().step(),
                VotingStep::Prevoted | VotingStep::Precommitted
            )
            && let Ok(proof) = self.participant().prevote_certificate()
        {
            let block = self
                .proposal
                .as_ref()
                .ok_or_else(|| local("missing proposal"))?
                .proposal
                .block
                .clone();
            self.valid = Some((block, proof));
            self.persist_cache()?;
            match self
                .participant_mut()
                .precommit()
                .map_err(NetworkNodeError::from)
            {
                Ok(vote) => self.record_local(vote)?,
                Err(NetworkNodeError::Input(_)) => {}
                Err(error) => return Err(error),
            }
        }
        let Some(event) = self.participant().timeout_event() else {
            return Ok(());
        };
        if self.timer.is_none_or(|(previous, _)| previous != event) {
            self.timer = Some((event, now));
        }
        // Growing round deadlines permit eventual overlap after delayed startup/reconnect.
        let duration = self
            .base_timeout
            .saturating_mul(event.round.saturating_add(1));
        if self
            .timer
            .is_some_and(|(_, started)| now.saturating_duration_since(started) >= duration)
        {
            if let Some(vote) = self.participant_mut().timeout(event)? {
                self.record_local(vote)?;
            } else {
                self.proposal = None;
                self.votes.clear();
                self.persist_cache()?;
            }
            self.timer = None;
        }
        Ok(())
    }

    fn propose_if_designated(&mut self) -> Result<(), NetworkNodeError> {
        if self.proposal.is_none()
            && self.participant().local().step() == VotingStep::AwaitingProposal
            && self.participant().proposer() == self.voter
        {
            let attempt = if let Some((block, proof)) = &self.valid {
                if proof.round() < self.round() {
                    let proposal = self
                        .participant()
                        .producer()
                        .execute_received_block(block.clone())?;
                    let proof = proof.clone();
                    Some(self.participant_mut().repropose(proposal, proof))
                } else {
                    None
                }
            } else if self.participant().local().locked().is_none() {
                Some(self.participant_mut().propose())
            } else {
                None
            };
            if let Some(result) = attempt {
                match result {
                    Ok(proposal) => {
                        encode_block(&proposal.proposal.block).map_err(input)?;
                        self.proposal = Some(proposal.clone());
                        self.persist_cache()?;
                        self.accept_available(&proposal)?;
                    }
                    Err(error) => match NetworkNodeError::from(error) {
                        NetworkNodeError::Input(_) => {}
                        error @ NetworkNodeError::Local(_) => return Err(error),
                    },
                }
            }
        }
        Ok(())
    }

    fn advance_height(&mut self) -> Result<(), NetworkNodeError> {
        let checkpoint = *self
            .storage
            .checkpoint()
            .ok_or_else(|| local("missing committed checkpoint"))?;
        let (producer, previous) = self
            .participant
            .take()
            .ok_or_else(|| local("missing participant"))?
            .into_parts();
        let voter = LocalBft::new(
            self.network.committee(producer.height())?,
            previous.into_signer(),
            self.network.hash,
        )
        .map_err(local)?;
        self.participant = Some(RoundRobinValidator::new(
            producer,
            voter,
            self.network.committee(checkpoint.height + 1)?,
        )?);
        self.proposal = None;
        self.valid = None;
        self.votes.clear();
        self.timer = None;
        self.persist_cache()
    }

    fn persist_cache(&self) -> Result<(), NetworkNodeError> {
        let bytes =
            encode_exchange(self.network.hash, &self.consensus_messages()).map_err(local)?;
        let temporary = self.cache_path.with_extension("pending");
        if temporary.exists() {
            std::fs::remove_file(&temporary).map_err(local)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(local)?;
        file.write_all(&bytes).map_err(local)?;
        file.sync_all().map_err(local)?;
        drop(file);
        std::fs::rename(temporary, &self.cache_path).map_err(local)?;
        #[cfg(unix)]
        std::fs::File::open(
            self.cache_path
                .parent()
                .ok_or_else(|| local("cache directory missing"))?,
        )
        .and_then(|directory| directory.sync_all())
        .map_err(local)?;
        Ok(())
    }

    fn restore_cache(&mut self) -> Result<(), NetworkNodeError> {
        let file = match std::fs::File::open(&self.cache_path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(local(error)),
        };
        let mut bytes = Vec::new();
        file.take(MAX_EXCHANGE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(local)?;
        let messages = decode_exchange(self.network.hash, &bytes).map_err(local)?;
        // Cache data is reauthenticated; it cannot relax the journal's signed watermark.
        for message in &messages {
            if let NetworkMessage::Vote(vote) = message
                && vote.height == self.request().height
                && vote.round == self.round()
            {
                self.participant()
                    .local()
                    .committee()
                    .verify_vote(vote)
                    .map_err(local)?;
                if self.participant().certificate().is_none() {
                    self.participant_mut().receive_vote(vote.clone())?;
                }
                self.votes.insert((vote.voter, vote.phase), vote.clone());
            }
        }
        for message in messages {
            match message {
                NetworkMessage::Proposal {
                    envelope,
                    block,
                    proof,
                } if envelope.height == self.request().height && envelope.round == self.round() => {
                    let proof = if proof.is_empty() {
                        None
                    } else {
                        Some(
                            PrevoteCertificate::decode(
                                self.participant().local().committee(),
                                &proof,
                            )
                            .map_err(local)?,
                        )
                    };
                    self.participant()
                        .local()
                        .verify_proposal(
                            self.participant().proposer(),
                            &envelope,
                            &block.header,
                            proof.as_ref(),
                        )
                        .map_err(local)?;
                    let proposal = SignedBlockProposal {
                        envelope,
                        proposal: self
                            .participant()
                            .producer()
                            .execute_received_block(block)?,
                        valid_round: proof,
                    };
                    if matches!(
                        self.participant().local().step(),
                        VotingStep::Prevoted | VotingStep::Precommitted
                    ) {
                        self.participant_mut().restore_proposal(&proposal)?;
                    }
                    self.proposal = Some(proposal);
                }
                NetworkMessage::ValidValue { block, proof }
                    if block.header.height == self.request().height =>
                {
                    let proof =
                        PrevoteCertificate::decode(self.participant().local().committee(), &proof)
                            .map_err(local)?;
                    if proof.block() != block.header.compute_hash() {
                        return Err(local("cached proof body mismatch"));
                    }
                    self.participant()
                        .producer()
                        .execute_received_block(block.clone())?;
                    self.valid = Some((block, proof));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
