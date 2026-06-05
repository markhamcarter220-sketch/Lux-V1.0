//! Boot subsystem — manifest parsing and kernel initialisation sequence.
//!
//! The boot sequence is the **only** path through which topology edges,
//! capability seeds, and resource quotas may be established.  It follows an
//! atomic, all-or-nothing contract:
//!
//! 1. Decode and cryptographically verify the manifest.
//! 2. Seed a `BootingGraph` with all declared edges and active nodes.
//! 3. Seed a `Ledger` with per-node quotas.
//! 4. **Seal** the graph — `BootingGraph::seal()` consumes the mutable graph
//!    and returns an `OperationalGraph`, making it structurally impossible to
//!    call `activate` or `permit_edge` ever again.
//! 5. Extend the TPM PCR with the manifest hash and record the attestation quote.
//! 6. Initialise the `Policy` enforcement point.
//!
//! If any step fails, `Err` is returned and **no partial state is retained**.
//! The caller receives either a fully initialised `BootState` or nothing.

pub mod credentials;
pub mod decode;
pub mod manifest;

pub use credentials::BootCredentials;
pub use decode::ManifestDecoder;
pub use manifest::Manifest;

use crate::{
    audit::AuditLog,
    auth::policy::Policy,
    consensus::{ConsensusProposal, PeerSet, Transport, run_consensus_proposal},
    hsm::HsmProvider,
    metabolism::ledger::Ledger,
    topology::graph::{BootingGraph, OperationalGraph},
    tpm::{NullTpm, TpmProvider, TpmQuote},
    types::Generation,
    Result,
};

/// Sealed, immutable kernel state produced by a successful boot sequence.
///
/// All three components are initialised atomically — they cannot be obtained
/// individually or in a partially-initialised form.  The `attestation` field
/// holds the TPM attestation quote from the boot sequence; it is all-zeros
/// when [`BootState::initialise`] is called with [`NullTpm`].
#[derive(Debug)]
pub struct BootState {
    pub(crate) graph:       OperationalGraph,
    pub(crate) ledger:      Ledger,
    pub(crate) policy:      Policy,
    attestation:            TpmQuote,
}

impl BootState {
    /// Returns a shared reference to the sealed topology graph.
    #[must_use]
    pub const fn graph(&self) -> &OperationalGraph {
        &self.graph
    }

    /// Returns a shared reference to the resource ledger.
    #[must_use]
    pub const fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Returns a mutable reference to the policy enforcement point.
    #[must_use]
    pub fn policy_mut(&mut self) -> &mut Policy {
        &mut self.policy
    }

    /// Returns the TPM attestation quote produced during `initialise`.
    ///
    /// The quote is all-zeros when [`NullTpm`] was used (default).
    #[must_use]
    pub const fn attestation_quote(&self) -> &TpmQuote {
        &self.attestation
    }

    /// Run a distributed consensus round to validate a topology traversal.
    ///
    /// The local sealed graph is checked first.  Its verdict — along with the
    /// votes from all peers in `peer_set` — determines the outcome:
    ///
    /// - **Committed** (`Ok(())`): a quorum of peers (including the local node)
    ///   accepted the traversal `src → dst`.
    /// - **Aborted** (`Err(TopologyViolation)`): the local graph denies the
    ///   edge, or fewer than `peer_set.quorum_threshold()` peers accepted.
    ///
    /// An `EventKind::TopologyChange` audit event is always appended to `audit`.
    ///
    /// # Single-node deployments
    ///
    /// Pass `PeerSet::new()` (empty) — the round is a local check with no
    /// network I/O.
    ///
    /// # Errors
    ///
    /// Returns `Err(TopologyViolation { src, dst })` when the traversal is
    /// denied by quorum or the local graph.
    pub fn run_topology_consensus<T: Transport>(
        &mut self,
        peer_set:  &PeerSet,
        proposal:  &ConsensusProposal,
        transport: &mut T,
        audit:     &mut AuditLog,
    ) -> Result<()> {
        let local_accept = self.graph.traverse(proposal.src, proposal.dst, audit).is_ok();
        let full_proposal = ConsensusProposal {
            round_id:          proposal.round_id,
            src:               proposal.src,
            dst:               proposal.dst,
            local_accept,
            local_attestation: *self.attestation.as_bytes(),
        };
        run_consensus_proposal(peer_set, &full_proposal, transport, audit)
    }

    /// Decode and verify `raw_manifest`, run the full boot sequence with a
    /// [`NullTpm`] (no TPM attestation), and return the sealed [`BootState`].
    ///
    /// This is the backward-compatible entry point.  All existing callers
    /// continue to work without modification.
    ///
    /// See [`BootState::initialise_with_tpm`] to record a real TPM attestation.
    ///
    /// # Errors
    ///
    /// Returns `Err` if manifest decoding, signature verification, or graph
    /// seeding fails.  No partial state is retained.
    pub fn initialise<H: HsmProvider>(
        raw_manifest: &[u8],
        credentials: &BootCredentials<H>,
    ) -> Result<Self> {
        let mut tpm = NullTpm;
        Self::initialise_with_tpm(raw_manifest, credentials, &mut tpm)
    }

    /// Decode and verify `raw_manifest`, extend the TPM PCR with the manifest
    /// hash, record the attestation quote, and return the sealed [`BootState`].
    ///
    /// Steps (all-or-nothing):
    ///  1. CBOR decode + signature verify via `credentials`
    ///  2. Seed topology graph edges
    ///  3. Seed resource ledger
    ///  4. Seal the graph (typestate: Booting → Operational)
    ///  5. Extend TPM PCR 0 with SHA-256 of the raw manifest bytes
    ///  6. Record the TPM attestation quote
    ///  7. Construct the policy enforcement point
    ///
    /// # Errors
    ///
    /// Returns `Err` if any step fails.  On `tpm.extend_pcr` failure the error
    /// is `ManifestInvalid` — the boot sequence is aborted (fail-closed).
    pub fn initialise_with_tpm<H: HsmProvider, T: TpmProvider>(
        raw_manifest: &[u8],
        credentials: &BootCredentials<H>,
        tpm: &mut T,
    ) -> Result<Self> {
        let manifest = ManifestDecoder::decode(raw_manifest, credentials)?;

        let mut booting = BootingGraph::new();
        let mut ledger  = Ledger::new();

        for edge in &manifest.edges {
            booting.activate(edge.src)?;
            booting.activate(edge.dst)?;
            booting.permit_edge(edge.src, edge.dst)?;
        }

        for q in &manifest.quotas {
            ledger.seed(q.node, q.ceiling);
        }

        let graph = booting.seal();

        // Step 5-6: TPM attestation over manifest bytes.
        // Use a fixed nonce of all-zeros (callers that need a stronger nonce
        // should call tpm.extend_pcr / tpm.quote directly).
        tpm.extend_pcr(0, raw_manifest)?;
        let attestation = tpm.quote(0, &[0u8; 32])?;

        let policy = Policy::new(Generation(0));

        Ok(Self { graph, ledger, policy, attestation })
    }
}
