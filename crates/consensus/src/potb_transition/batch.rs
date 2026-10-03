// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Canonical inclusion order and bounded nesting for `PoTB` system batches.

use super::encoding::{read_field, write_field};
use crate::{
    admission::AdmissionCertificate,
    history::HistoricalEvidence,
    rotation::{MAX_ROTATION_VALIDATORS, VrfBatch},
};
use codec::{DecodeError, Decoder};
use types::{Hash256, hash::domain_hash};

/// Exact system input: complete parent VRF roster, offences, then authorized admissions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PotbBatch {
    contributions: VrfBatch,
    evidence: Vec<HistoricalEvidence>,
    admissions: Vec<AdmissionCertificate>,
}

impl PotbBatch {
    /// Bounded independently of chain length; checks precede decoder allocations.
    pub const MAX_BYTES: usize = 14
        + VrfBatch::MAX_BYTES
        + MAX_ROTATION_VALIDATORS
            * (8 + HistoricalEvidence::MAX_BYTES + AdmissionCertificate::MAX_BYTES);

    /// Canonicalizes arrival order. Multiple offences for one identity or duplicate
    /// candidates are rejected instead of offering alternate stacking/order rules.
    pub fn new(
        contributions: VrfBatch,
        mut evidence: Vec<HistoricalEvidence>,
        mut admissions: Vec<AdmissionCertificate>,
    ) -> Result<Self, DecodeError> {
        if evidence.len() > MAX_ROTATION_VALIDATORS || admissions.len() > MAX_ROTATION_VALIDATORS {
            return Err(DecodeError::LimitExceeded);
        }
        evidence.sort_by_key(|e| e.evidence().voter());
        admissions.sort_by_key(|a| a.request().candidate());
        let result = Self {
            contributions,
            evidence,
            admissions,
        };
        result.validate_order()?;
        Ok(result)
    }

    /// Complete contributions; authentication also requires the parent roster.
    #[must_use]
    pub const fn contributions(&self) -> &VrfBatch {
        &self.contributions
    }

    /// Offences in strictly increasing accused-identity order.
    #[must_use]
    pub fn evidence(&self) -> &[HistoricalEvidence] {
        &self.evidence
    }

    /// Admissions in strictly increasing candidate-identity order.
    #[must_use]
    pub fn admissions(&self) -> &[AdmissionCertificate] {
        &self.admissions
    }

    /// Commits exact canonical inclusion, including all signatures and historical witnesses.
    pub fn commitment(&self) -> Result<Hash256, DecodeError> {
        Ok(domain_hash(b"astrolune.potb.batch.v1", &self.to_bytes()?))
    }

    fn validate_order(&self) -> Result<(), DecodeError> {
        if self.evidence.len() > MAX_ROTATION_VALIDATORS
            || self.admissions.len() > MAX_ROTATION_VALIDATORS
        {
            return Err(DecodeError::LimitExceeded);
        }
        if self
            .evidence
            .windows(2)
            .any(|p| p[0].evidence().voter() >= p[1].evidence().voter())
            || self
                .admissions
                .windows(2)
                .any(|p| p[0].request().candidate() >= p[1].request().candidate())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    /// Exact framing. Canonical bytes alone do not prove historical or current authority.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate_order()?;
        let mut bytes = b"ALPTBT01".to_vec();
        write_field(&mut bytes, &self.contributions.to_bytes()?)?;
        bytes.push(u8::try_from(self.evidence.len()).map_err(|_| DecodeError::LimitExceeded)?);
        for evidence in &self.evidence {
            write_field(&mut bytes, &evidence.to_bytes()?)?;
        }
        bytes.push(u8::try_from(self.admissions.len()).map_err(|_| DecodeError::LimitExceeded)?);
        for admission in &self.admissions {
            write_field(&mut bytes, &admission.to_bytes()?)?;
        }
        Ok(bytes)
    }

    /// Preflights both complete lists and nested field bounds before decoding owned values.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALPTBT01" {
            return Err(DecodeError::Unsupported);
        }
        let contributions = read_field(&mut decoder, VrfBatch::MAX_BYTES)?;
        let evidence = read_list(&mut decoder, HistoricalEvidence::MAX_BYTES)?;
        let admissions = read_list(&mut decoder, AdmissionCertificate::MAX_BYTES)?;
        decoder.finish()?;
        let result = Self {
            contributions: VrfBatch::from_bytes(contributions)?,
            evidence: evidence
                .into_iter()
                .map(HistoricalEvidence::from_bytes)
                .collect::<Result<_, _>>()?,
            admissions: admissions
                .into_iter()
                .map(AdmissionCertificate::from_bytes)
                .collect::<Result<_, _>>()?,
        };
        result.validate_order()?;
        Ok(result)
    }
}

fn read_list<'a>(decoder: &mut Decoder<'a>, maximum: usize) -> Result<Vec<&'a [u8]>, DecodeError> {
    let count = usize::from(decoder.read_u8()?);
    if count > MAX_ROTATION_VALIDATORS {
        return Err(DecodeError::LimitExceeded);
    }
    (0..count).map(|_| read_field(decoder, maximum)).collect()
}
