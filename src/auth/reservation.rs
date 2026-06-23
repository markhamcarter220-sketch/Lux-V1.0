//! Reservation ledger — Phase 2 ("RESERVE") of the Capability-Signed
//! Message IPC protocol.
//!
//! Specification: `docs/ipc/IPC-SPEC.md`. This module implements only the
//! state shapes and ledger operations that document defines for Phase 2.
//! **It is not wired into `Policy::check`, `AuditLog`, or any IPC transport
//! — no other module in this crate constructs a [`Reservation`].** Wiring
//! Phase 1 (CHECK) and Phase 3 (EXECUTE) into the kernel's existing
//! enforcement points is separate, not-yet-approved work; this module does
//! not modify any of the four invariant enforcement points
//! (`Policy::check`, `Capability::authorises`, `Ledger::deduct`,
//! `OperationalGraph::traverse`).
//!
//! # Relationship to `RevocationLedger`
//!
//! Structurally parallel to [`crate::auth::revocation::RevocationLedger`]:
//! `no_std`, no heap allocation, fixed capacity, single-owner mutation.
//! Unlike `RevocationLedger` (an `FnvIndexSet`, O(1) amortised), this
//! ledger stores full records and is searched linearly — bounded by
//! `MAX_RESERVATIONS` (256), the same order of magnitude as the existing
//! O(N) nonce-replay scan in `Policy::check` (`NONCE_WINDOW` = 256).
//!
//! # Cascade rule
//!
//! Revoking the capability nonce a reservation was derived from must also
//! invalidate the reservation (IPC-SPEC.md Phase 2, "Cascade rule") —
//! [`ReservationLedger::revoke_by_origin_nonce`] implements this. Nothing
//! calls it automatically yet; a future wiring step must call it from
//! wherever `Policy::revoke_capability` is called.

use heapless::Vec as HVec;

use crate::{
    auth::capability::CapabilitySet,
    error::Error,
    types::{Generation, NodeId, MAX_RESERVATIONS, MAX_RESERVATION_TTL},
    Result,
};

/// Fresh, receiver-issued identifier for a single reservation.
///
/// Disjoint from [`Capability`](crate::auth::capability::Capability) nonces
/// by construction: [`ReservationLedger`] issues values from its own
/// monotonic counter, never derived from or compared against a `cap.nonce`
/// (IPC-SPEC.md Claims Discipline, claim 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReservationId(u64);

impl ReservationId {
    /// Returns the raw identifier value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Bounded time-to-live for a reservation, in the caller's logical-tick
/// units. The kernel owns no wall clock (see the `timestamp` field doc on
/// [`crate::audit::AuditEvent`]).
///
/// Construction enforces `0 < ttl <= MAX_RESERVATION_TTL`
/// (IPC-SPEC.md Phase 2, "Failure / rejection modes").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReservationTtl(u64);

impl ReservationTtl {
    /// Construct a TTL, rejecting zero and out-of-bound values.
    #[must_use]
    pub const fn new(ticks: u64) -> Option<Self> {
        if ticks == 0 || ticks > MAX_RESERVATION_TTL {
            None
        } else {
            Some(Self(ticks))
        }
    }

    /// Returns the raw tick count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Lifecycle state of a single reservation (IPC-SPEC.md Phase 2).
///
/// `Revoked`, `Expired`, and `Consumed` are terminal — none transitions
/// back to `Active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationStatus {
    /// Eligible to be granted an [`ExecutionGrant`].
    Active,
    /// Explicitly revoked, directly or via cascade from the originating
    /// capability's nonce (IPC-SPEC.md Phase 2, "Cascade rule").
    Revoked,
    /// TTL elapsed before being granted or consumed.
    Expired,
    /// Already committed by Phase 3 ([`ReservationLedger::consume`]);
    /// cannot be reused.
    Consumed,
}

/// A single RESERVE-phase commitment (IPC-SPEC.md Phase 2).
///
/// `generation` is a snapshot taken at CHECK time (Phase 1), not re-read
/// from the live `Policy` — a future EXECUTE wiring step must compare this
/// snapshot against the receiver's *current* generation, not assume it is
/// still current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    id: ReservationId,
    node: NodeId,
    action: CapabilitySet,
    generation: Generation,
    /// Nonce of the capability whose CHECK produced this reservation.
    /// Carried so a revocation of that nonce can cascade
    /// (`revoke_by_origin_nonce`).
    origin_nonce: u64,
    created_at: u64,
    ttl: ReservationTtl,
    status: ReservationStatus,
}

impl Reservation {
    /// Returns this reservation's identifier.
    #[must_use]
    pub const fn id(self) -> ReservationId {
        self.id
    }

    /// Returns the node this reservation is bound to.
    #[must_use]
    pub const fn node(self) -> NodeId {
        self.node
    }

    /// Returns the action this reservation authorises.
    #[must_use]
    pub const fn action(self) -> CapabilitySet {
        self.action
    }

    /// Returns the generation snapshot taken at CHECK time.
    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }

    /// Returns the originating capability's nonce.
    #[must_use]
    pub const fn origin_nonce(self) -> u64 {
        self.origin_nonce
    }

    /// Returns the stored lifecycle status (not lazily-expired — see
    /// [`ReservationLedger::effective_status`] for the expiry-aware view).
    #[must_use]
    pub const fn status(self) -> ReservationStatus {
        self.status
    }

    /// Returns the absolute logical tick at which this reservation expires.
    /// Computed via saturating addition — never wraps.
    #[must_use]
    pub const fn expires_at(self) -> u64 {
        self.created_at.saturating_add(self.ttl.get())
    }
}

/// Output of a successful [`ReservationLedger::grant`] call.
///
/// IPC-SPEC.md Phase 2, "Outputs"; consumed by a future Phase 3 (EXECUTE)
/// wiring step. Carries no authority beyond what the originating
/// [`Reservation`] still holds at the moment EXECUTE re-checks it — see
/// IPC-SPEC.md Phase 3, "Live revocation channel".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionGrant {
    reservation_id: ReservationId,
    generation: Generation,
    action: CapabilitySet,
    expires_at: u64,
}

impl ExecutionGrant {
    /// Returns the reservation this grant was derived from.
    #[must_use]
    pub const fn reservation_id(self) -> ReservationId {
        self.reservation_id
    }

    /// Returns the generation snapshot carried from the reservation.
    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }

    /// Returns the action this grant authorises.
    #[must_use]
    pub const fn action(self) -> CapabilitySet {
        self.action
    }

    /// Returns the absolute logical tick at which this grant expires.
    #[must_use]
    pub const fn expires_at(self) -> u64 {
        self.expires_at
    }
}

/// Receiver-local, bounded store of outstanding reservations.
///
/// IPC-SPEC.md Phase 2. No heap allocation; fixed capacity
/// `MAX_RESERVATIONS`; single-owner mutation, mirroring
/// [`crate::auth::revocation::RevocationLedger`].
#[derive(Debug)]
pub struct ReservationLedger {
    reservations: HVec<Reservation, MAX_RESERVATIONS>,
    next_id: u64,
}

impl ReservationLedger {
    /// Constructs an empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reservations: HVec::new(),
            next_id: 0,
        }
    }

    fn find(&self, id: ReservationId) -> Option<&Reservation> {
        self.reservations.iter().find(|r| r.id == id)
    }

    fn find_mut(&mut self, id: ReservationId) -> Option<&mut Reservation> {
        self.reservations.iter_mut().find(|r| r.id == id)
    }

    /// Open a new reservation (IPC-SPEC.md Phase 2, "State created").
    ///
    /// `now` is the caller-supplied logical tick; the reservation's
    /// absolute expiry is `now.saturating_add(ttl.get())`.
    ///
    /// # Errors
    /// Returns `Err(Error::ReservationDenied)` if the ledger is at
    /// capacity (`MAX_RESERVATIONS`). Fail-closed: the caller must wait for
    /// capacity to free up via expiry, consumption, or revocation rather
    /// than overwrite an existing reservation.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        node: NodeId,
        action: CapabilitySet,
        generation: Generation,
        origin_nonce: u64,
        ttl: ReservationTtl,
        now: u64,
    ) -> Result<ReservationId> {
        let id = ReservationId(self.next_id);
        let reservation = Reservation {
            id,
            node,
            action,
            generation,
            origin_nonce,
            created_at: now,
            ttl,
            status: ReservationStatus::Active,
        };
        self.reservations
            .push(reservation)
            .map_err(|_| Error::ReservationDenied {
                reason: "reservation capacity exhausted",
            })?;
        self.next_id = self.next_id.saturating_add(1);
        Ok(id)
    }

    /// Returns the effective status of `id`: stored `status`, except
    /// `Active` reservations whose TTL has elapsed are reported as
    /// `Expired` without mutating stored state. Read-only — matches
    /// IPC-SPEC.md Phase 3's framing of the "live revocation channel" as a
    /// check, not a mutation.
    #[must_use]
    pub fn effective_status(&self, id: ReservationId, now: u64) -> Option<ReservationStatus> {
        let r = self.find(id)?;
        Some(match r.status {
            ReservationStatus::Active if now >= r.expires_at() => ReservationStatus::Expired,
            other => other,
        })
    }

    /// Explicitly revoke a single reservation (IPC-SPEC.md Phase 2,
    /// "Revocation during RESERVE — mechanism").
    ///
    /// Returns `true` if `id` existed and was `Active` (and is now
    /// `Revoked`); `false` if it did not exist or was already in a
    /// terminal state. Re-revoking is a no-op, not an error.
    pub fn revoke(&mut self, id: ReservationId) -> bool {
        match self.find_mut(id) {
            Some(r) if matches!(r.status, ReservationStatus::Active) => {
                r.status = ReservationStatus::Revoked;
                true
            }
            _ => false,
        }
    }

    /// Cascade revocation: invalidate every `Active` reservation derived
    /// from capability nonce `origin_nonce` (IPC-SPEC.md Phase 2, "Cascade
    /// rule"). Returns the count of reservations transitioned to
    /// `Revoked`. No caller invokes this automatically yet — see module
    /// doc.
    pub fn revoke_by_origin_nonce(&mut self, origin_nonce: u64) -> usize {
        let mut count = 0usize;
        for r in &mut self.reservations {
            if r.origin_nonce == origin_nonce && matches!(r.status, ReservationStatus::Active) {
                r.status = ReservationStatus::Revoked;
                count = count.saturating_add(1);
            }
        }
        count
    }

    /// Phase 2 output (IPC-SPEC.md "RESERVE — Outputs"). Read-only: does
    /// not consume the reservation. Re-granting an `Active` reservation is
    /// permitted; only [`Self::consume`] (Phase 3's commit step) is
    /// one-shot.
    ///
    /// # Errors
    /// Returns `Err(Error::ReservationDenied)` if `id` does not exist or
    /// its effective status is not `Active`.
    pub fn grant(&self, id: ReservationId, now: u64) -> Result<ExecutionGrant> {
        let r = self.find(id).ok_or(Error::ReservationDenied {
            reason: "reservation not active",
        })?;
        let active = matches!(r.status, ReservationStatus::Active) && now < r.expires_at();
        if !active {
            return Err(Error::ReservationDenied {
                reason: "reservation not active",
            });
        }
        Ok(ExecutionGrant {
            reservation_id: r.id,
            generation: r.generation,
            action: r.action,
            expires_at: r.expires_at(),
        })
    }

    /// Phase 3 commit step (IPC-SPEC.md "EXECUTE — Outputs"). One-shot:
    /// marks the reservation `Consumed` so the same grant cannot be
    /// replayed into a second EXECUTE. No caller invokes this yet — Phase 3
    /// is not wired into the kernel.
    ///
    /// # Errors
    /// Returns `Err(Error::ReservationDenied)` if `id` does not exist or
    /// its effective status is not `Active`.
    pub fn consume(&mut self, id: ReservationId, now: u64) -> Result<()> {
        let expires_at = match self.find(id) {
            Some(r) if matches!(r.status, ReservationStatus::Active) => r.expires_at(),
            _ => {
                return Err(Error::ReservationDenied {
                    reason: "reservation not active",
                })
            }
        };
        if now >= expires_at {
            return Err(Error::ReservationDenied {
                reason: "reservation not active",
            });
        }
        // Safe: the lookup above confirmed presence and `Active` status,
        // and no mutation can occur between the two lookups within this
        // single `&mut self` call (single-threaded, no reentrancy).
        if let Some(r) = self.find_mut(id) {
            r.status = ReservationStatus::Consumed;
        }
        Ok(())
    }

    /// Returns the number of reservations currently stored (any status).
    #[must_use]
    pub fn len(&self) -> usize {
        self.reservations.len()
    }

    /// Returns `true` if the ledger holds no reservations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reservations.is_empty()
    }

    /// Clear all reservations. Mirrors `RevocationLedger::clear` /
    /// `Policy::rotate_generation`; no caller invokes this yet (see module
    /// doc).
    pub fn clear(&mut self) {
        self.reservations.clear();
    }
}

impl Default for ReservationLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU32;

    fn nz(n: u32) -> NodeId {
        NonZeroU32::new(n).unwrap()
    }

    fn ttl(ticks: u64) -> ReservationTtl {
        ReservationTtl::new(ticks).expect("test ttl in bounds")
    }

    #[test]
    fn ttl_rejects_zero_and_out_of_bounds() {
        assert!(ReservationTtl::new(0).is_none());
        assert!(ReservationTtl::new(MAX_RESERVATION_TTL).is_some());
        assert!(ReservationTtl::new(MAX_RESERVATION_TTL + 1).is_none());
    }

    #[test]
    fn reserve_then_grant_succeeds_within_ttl() {
        let mut ledger = ReservationLedger::new();
        let id = ledger
            .reserve(
                nz(1),
                CapabilitySet::ALLOC_RESOURCE,
                Generation(1),
                42,
                ttl(10),
                0,
            )
            .expect("reserve must succeed under capacity");
        let grant = ledger.grant(id, 5).expect("grant within ttl must succeed");
        assert_eq!(grant.reservation_id(), id);
        assert_eq!(grant.action(), CapabilitySet::ALLOC_RESOURCE);
        assert_eq!(grant.generation(), Generation(1));
    }

    #[test]
    fn grant_after_ttl_elapsed_is_denied() {
        let mut ledger = ReservationLedger::new();
        let id = ledger
            .reserve(
                nz(1),
                CapabilitySet::ALLOC_RESOURCE,
                Generation(1),
                42,
                ttl(10),
                0,
            )
            .unwrap();
        assert!(matches!(
            ledger.grant(id, 10),
            Err(Error::ReservationDenied { .. })
        ));
        assert_eq!(
            ledger.effective_status(id, 10),
            Some(ReservationStatus::Expired)
        );
    }

    #[test]
    fn revoke_then_grant_is_denied() {
        let mut ledger = ReservationLedger::new();
        let id = ledger
            .reserve(
                nz(1),
                CapabilitySet::ALLOC_RESOURCE,
                Generation(1),
                42,
                ttl(10),
                0,
            )
            .unwrap();
        assert!(ledger.revoke(id));
        assert!(!ledger.revoke(id), "re-revoking must be a no-op, not true");
        assert!(matches!(
            ledger.grant(id, 1),
            Err(Error::ReservationDenied { .. })
        ));
    }

    #[test]
    fn cascade_revocation_invalidates_all_derived_reservations() {
        let mut ledger = ReservationLedger::new();
        let origin_nonce = 7u64;
        let a = ledger
            .reserve(
                nz(1),
                CapabilitySet::ALLOC_RESOURCE,
                Generation(1),
                origin_nonce,
                ttl(10),
                0,
            )
            .unwrap();
        let b = ledger
            .reserve(
                nz(1),
                CapabilitySet::SCHEDULE,
                Generation(1),
                origin_nonce,
                ttl(10),
                0,
            )
            .unwrap();
        let unrelated = ledger
            .reserve(
                nz(2),
                CapabilitySet::SCHEDULE,
                Generation(1),
                999,
                ttl(10),
                0,
            )
            .unwrap();

        let revoked_count = ledger.revoke_by_origin_nonce(origin_nonce);
        assert_eq!(revoked_count, 2);

        assert!(matches!(
            ledger.grant(a, 1),
            Err(Error::ReservationDenied { .. })
        ));
        assert!(matches!(
            ledger.grant(b, 1),
            Err(Error::ReservationDenied { .. })
        ));
        assert!(
            ledger.grant(unrelated, 1).is_ok(),
            "cascade must not touch reservations from a different origin nonce"
        );
    }

    #[test]
    fn consume_is_one_shot() {
        let mut ledger = ReservationLedger::new();
        let id = ledger
            .reserve(
                nz(1),
                CapabilitySet::ALLOC_RESOURCE,
                Generation(1),
                42,
                ttl(10),
                0,
            )
            .unwrap();
        ledger.consume(id, 1).expect("first consume must succeed");
        assert!(
            matches!(ledger.consume(id, 1), Err(Error::ReservationDenied { .. })),
            "second consume of the same reservation must be denied (no replay)"
        );
        assert!(
            matches!(ledger.grant(id, 1), Err(Error::ReservationDenied { .. })),
            "a consumed reservation must not be re-grantable"
        );
    }

    #[test]
    fn reserve_denies_at_capacity() {
        let mut ledger = ReservationLedger::new();
        for i in 0..MAX_RESERVATIONS {
            ledger
                .reserve(
                    nz(1),
                    CapabilitySet::SCHEDULE,
                    Generation(1),
                    i as u64,
                    ttl(10),
                    0,
                )
                .expect("must succeed under capacity");
        }
        assert!(matches!(
            ledger.reserve(
                nz(1),
                CapabilitySet::SCHEDULE,
                Generation(1),
                9999,
                ttl(10),
                0
            ),
            Err(Error::ReservationDenied { .. })
        ));
        assert_eq!(ledger.len(), MAX_RESERVATIONS);
    }

    #[test]
    fn clear_empties_the_ledger() {
        let mut ledger = ReservationLedger::new();
        ledger
            .reserve(nz(1), CapabilitySet::SCHEDULE, Generation(1), 1, ttl(10), 0)
            .unwrap();
        assert!(!ledger.is_empty());
        ledger.clear();
        assert!(ledger.is_empty());
    }
}
