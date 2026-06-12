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

use sha2::{Digest, Sha256};

use crate::{
    audit::{AuditLog, EventKind, UNTIMED},
    auth::policy::Policy,
    consensus::{PeerSet, RaftNode, RaftTransport},
    error::{DenialClass, Error},
    hsm::HsmProvider,
    metabolism::ledger::Ledger,
    topology::graph::{BootingGraph, OperationalGraph},
    tpm::{NullTpm, TpmProvider, TpmQuote},
    types::{Generation, NodeId},
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
    pub(crate) graph: OperationalGraph,
    pub(crate) ledger: Ledger,
    pub(crate) policy: Policy,
    attestation: TpmQuote,
    manifest_hash: [u8; 32],
    local_id: NodeId,
}

impl BootState {
    /// Returns the local node ID used for Raft leader election.
    ///
    /// Defaults to node 1.  Override with [`BootState::with_local_id`] for
    /// multi-node deployments where this node is not node 1.
    #[must_use]
    pub const fn local_id(&self) -> NodeId {
        self.local_id
    }

    /// Return a copy of `self` with `local_id` set to `id`.
    ///
    /// Used by multi-node deployments that are not node 1 in the topology.
    #[must_use]
    pub const fn with_local_id(mut self, id: NodeId) -> Self {
        self.local_id = id;
        self
    }

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

    /// Returns the SHA-256 hash of the raw manifest bytes used during boot.
    ///
    /// This is the measurement value extended into the TPM PCR during
    /// [`BootState::initialise_with_tpm`].
    #[must_use]
    pub const fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// Produce a fresh [`BootAttestation`] by quoting the boot PCR with `nonce`.
    ///
    /// The nonce should be a verifier-supplied random value (challenge-response).
    /// The returned attestation can be sent to the verifier, who reconstructs
    /// the expected PCR state and calls [`crate::tpm::attestation::BootAttestation::verify`].
    ///
    /// # Errors
    ///
    /// Returns `Err(ManifestInvalid)` if the TPM cannot produce a quote.
    pub fn produce_attestation<T: TpmProvider>(
        &self,
        tpm: &T,
        nonce: [u8; 32],
    ) -> Result<crate::tpm::attestation::BootAttestation> {
        let quote = tpm.quote(0, &nonce)?;
        Ok(crate::tpm::attestation::BootAttestation::new(
            self.manifest_hash,
            0,
            nonce,
            quote,
        ))
    }

    /// Run a Raft consensus round to validate a topology traversal.
    ///
    /// The local sealed graph is the authoritative gate: if the edge
    /// `(src, dst)` is not declared in the boot manifest, the operation
    /// aborts immediately regardless of what peer votes might say (fail-closed).
    /// Only if the local graph permits the edge does the node proceed to
    /// elect itself Raft leader (using [`BootState::local_id`] as the candidate
    /// identity) and replicate the entry to peers.
    ///
    /// - **Committed** (`Ok(())`): a quorum agreed to the entry.
    /// - **Aborted** (`Err(TopologyViolation)`): local graph denied the edge,
    ///   or leader election failed, or fewer than quorum peers acknowledged.
    ///
    /// An `EventKind::TopologyChange` audit event is always appended for the
    /// consensus outcome (in addition to the `TopologyTraverse` event emitted
    /// by the local graph check).
    ///
    /// # Single-node deployments
    ///
    /// Pass `PeerSet::new()` (empty) — the node becomes leader immediately and
    /// commits without any network I/O.
    ///
    /// # Errors
    ///
    /// Returns `Err(TopologyViolation { src, dst })` when the traversal is
    /// denied by the local graph or consensus fails to reach quorum.
    pub fn run_topology_consensus<T: RaftTransport>(
        &mut self,
        peer_set: &PeerSet,
        src: NodeId,
        dst: NodeId,
        transport: &mut T,
        audit: &mut AuditLog,
    ) -> Result<()> {
        // I4: local sealed graph is the authoritative gate (fail-closed).
        let local_ok = self.graph.traverse(src, dst, audit).is_ok();
        if !local_ok {
            return Err(Error::TopologyViolation {
                src: src.get(),
                dst: dst.get(),
            });
        }

        let mut node = RaftNode::new(self.local_id, peer_set);
        node.start_election(transport);

        if !node.is_leader() {
            while let Some((from, msg)) = transport.recv() {
                let _ = node.step(from, msg, transport);
                if node.is_leader() {
                    break;
                }
            }
        }

        if !node.is_leader() {
            audit.append(
                EventKind::TopologyChange,
                src.get(),
                UNTIMED,
                Some((DenialClass::Halt, "topology consensus not reached")),
            );
            return Err(Error::TopologyViolation {
                src: src.get(),
                dst: dst.get(),
            });
        }

        node.propose(src, dst, transport)?;

        let mut committed = node.commit_index() >= node.log_len();
        if !committed {
            while let Some((from, msg)) = transport.recv() {
                if node.step(from, msg, transport).is_some() {
                    committed = true;
                    break;
                }
            }
        }

        let denial = (!committed).then_some((DenialClass::Halt, "topology consensus not reached"));
        audit.append(EventKind::TopologyChange, src.get(), UNTIMED, denial);

        if committed {
            Ok(())
        } else {
            Err(Error::TopologyViolation {
                src: src.get(),
                dst: dst.get(),
            })
        }
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
        let manifest_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(raw_manifest);
            h.finalize().into()
        };

        let manifest = ManifestDecoder::decode(raw_manifest, credentials)?;

        let mut booting = BootingGraph::new();
        let mut ledger = Ledger::new();

        for edge in &manifest.edges {
            booting.activate(edge.src)?;
            booting.activate(edge.dst)?;
            booting.permit_edge(edge.src, edge.dst)?;
        }

        for q in &manifest.quotas {
            ledger.seed(q.node, q.ceiling)?;
        }

        let graph = booting.seal();

        // Step 5-6: TPM attestation over manifest bytes.
        // Use a fixed nonce of all-zeros (callers that need a stronger nonce
        // should call tpm.extend_pcr / tpm.quote directly).
        tpm.extend_pcr(0, raw_manifest)?;
        let attestation = tpm.quote(0, &[0u8; 32])?;

        let policy = Policy::new(Generation(0));

        Ok(Self {
            graph,
            ledger,
            policy,
            attestation,
            manifest_hash,
            local_id: NodeId::MIN,
        })
    }
}
