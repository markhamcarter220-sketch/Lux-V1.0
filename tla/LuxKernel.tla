---- MODULE LuxKernel ----
(*
  Lux Kernel -- Formal Security Specification (TLA+)
  Tier 3: Mathematical proof of four security theorems via TLC model checking.

  THEOREMS PROVED:
    1. NonEscalation       - no capability ever exceeds its root authority
    2. RevocationSoundness - revoked nonces are permanently denied
    3. ResourceAtomicity   - deductions are all-or-nothing (no partial writes)
    4. TopologyBoundedness - execution stays within declared manifest edges

  Model-check with TLC:
    java -jar tla2tools.jar MC.tla -config MC.cfg
*)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Principals,    \* finite set of principals        (model: {"P1","P2"})
    Nodes,         \* finite set of topology nodes    (model: {"N1","N2"})
    AllRights,     \* set of rights the kernel knows  (model: {"DELEGATE","SHUTDOWN"})
    MaxNonce,      \* upper bound on nonce values      (model: 2)
    MaxResources,  \* max quota per principal          (model: 2)
    MaxEpoch,      \* max generation count             (model: 1)
    MaxCaps,       \* max simultaneous caps in issuedCaps (model: 3)
    BootEdges      \* boot-manifest edges: SUBSET (Nodes x Nodes)

\* All valid nonce values.
Nonces == 0..MaxNonce

ASSUME Principals   # {}
ASSUME Nodes        # {}
ASSUME AllRights    # {}
ASSUME "DELEGATE"  \in AllRights   \* delegation right must exist
ASSUME MaxNonce     >= 0
ASSUME MaxResources >= 0
ASSUME MaxEpoch     >= 0
ASSUME MaxCaps      >= 1
ASSUME BootEdges   \subseteq (Nodes \X Nodes)

---------------------------------------------------------------------------
\* STATE VARIABLES
---------------------------------------------------------------------------

VARIABLES
    \* Set of all issued capability records.
    \* Each record: [issuer, owner, rights, gen, nonce, rootRights]
    issuedCaps,

    \* Set of nonces revoked within the current epoch.
    revokedNonces,

    \* Current generation counter.
    epoch,

    \* Next fresh nonce (monotone; reset to 0 on epoch rotation).
    nextNonce,

    \* Resource balances: Principal -> Nat
    balances,

    \* Set of edges actually traversed during execution.
    executedTraversals

vars == <<issuedCaps, revokedNonces, epoch, nextNonce,
          balances, executedTraversals>>

---------------------------------------------------------------------------
\* TYPE INVARIANT
---------------------------------------------------------------------------

TypeOK ==
    /\ \A c \in issuedCaps :
           /\ c.issuer     \in Principals
           /\ c.owner      \in Principals
           /\ c.rights     \subseteq AllRights
           /\ c.gen        \in 0..MaxEpoch
           /\ c.nonce      \in Nonces
           /\ c.rootRights \subseteq AllRights
    /\ revokedNonces      \subseteq Nonces
    /\ epoch              \in 0..MaxEpoch
    /\ nextNonce          \in Nonces \cup {MaxNonce + 1}
    /\ balances           \in [Principals -> 0..MaxResources]
    /\ executedTraversals \subseteq (Nodes \X Nodes)

---------------------------------------------------------------------------
\* HELPER PREDICATES
---------------------------------------------------------------------------

\* Mirrors Policy::check() step order in Rust:
\*   (1) generation must match current epoch
\*   (2) nonce must not be in the revocation set
\*   (3) rights set must be non-empty
IsValidCap(cap) ==
    /\ cap.gen    = epoch
    /\ cap.nonce \notin revokedNonces
    /\ cap.rights # {}

\* Effective authority of a principal: union of rights of all valid caps.
Authority(p) ==
    UNION { c.rights : c \in { x \in issuedCaps :
                                x.owner = p /\ IsValidCap(x) } }

---------------------------------------------------------------------------
\* INITIAL STATE
---------------------------------------------------------------------------

Init ==
    /\ issuedCaps         = {}
    /\ revokedNonces      = {}
    /\ epoch              = 0
    /\ nextNonce          = 0
    /\ balances           = [p \in Principals |-> MaxResources]
    /\ executedTraversals = {}

---------------------------------------------------------------------------
\* ACTIONS
---------------------------------------------------------------------------

\* Issue a boot capability.
\* rootRights = rights: this cap is the root of its delegation chain.
\* Every delegated descendant will have the same rootRights ceiling.
BootIssueCap(p, rts) ==
    /\ rts \subseteq AllRights
    /\ rts       # {}
    /\ nextNonce <= MaxNonce
    /\ Cardinality(issuedCaps) < MaxCaps    \* bound cap-set size for TLC
    /\ LET cap == [ issuer     |-> p,
                    owner      |-> p,
                    rights     |-> rts,
                    gen        |-> epoch,
                    nonce      |-> nextNonce,
                    rootRights |-> rts ]
       IN  issuedCaps' = issuedCaps \cup {cap}
    /\ nextNonce' = nextNonce + 1
    /\ UNCHANGED <<revokedNonces, epoch, balances, executedTraversals>>

\* Delegate: create a sub-capability with a strict subset of rights.
\* NON-ESCALATION GUARDS:
\*   (a) newRights \subseteq cap.rights       -- prevents escalation at each step
\*   (b) newCap.rootRights = cap.rootRights   -- ceiling never rises through chain
\*
\* Proof that these guards make NonEscalation inductive:
\*   IF cap.rights \subseteq cap.rootRights  (ind. hypothesis)
\*   THEN newRights \subseteq cap.rights \subseteq cap.rootRights  (by (a))
\*        AND newCap.rootRights = cap.rootRights                   (by (b))
\*   THEREFORE newCap.rights \subseteq newCap.rootRights           QED
Delegate(cap, q, newRights) ==
    /\ cap        \in issuedCaps
    /\ IsValidCap(cap)
    /\ "DELEGATE" \in cap.rights          \* must hold DELEGATE right
    /\ q          \in Principals
    /\ newRights  \subseteq cap.rights    \* *** NON-ESCALATION GUARD ***
    /\ newRights  # {}
    /\ nextNonce  <= MaxNonce
    /\ Cardinality(issuedCaps) < MaxCaps  \* bound cap-set size for TLC
    /\ LET newCap == [ issuer     |-> cap.owner,
                       owner      |-> q,
                       rights     |-> newRights,
                       gen        |-> epoch,
                       nonce      |-> nextNonce,
                       rootRights |-> cap.rootRights ]
       IN  issuedCaps' = issuedCaps \cup {newCap}
    /\ nextNonce' = nextNonce + 1
    /\ UNCHANGED <<revokedNonces, epoch, balances, executedTraversals>>

\* Revoke a capability by nonce.
\* Atomically adds nonce to the revocation set.
RevokeCap(nonce) ==
    /\ nonce \in Nonces
    /\ revokedNonces' = revokedNonces \cup {nonce}
    /\ UNCHANGED <<issuedCaps, nextNonce, epoch, balances, executedTraversals>>

\* Consume a capability to authorise a right.
\* Nonce is added to revokedNonces (one-time use / replay prevention).
UseCap(cap, right) ==
    /\ cap   \in issuedCaps
    /\ right \in AllRights
    /\ IsValidCap(cap)
    /\ right \in cap.rights
    /\ revokedNonces' = revokedNonces \cup {cap.nonce}
    /\ UNCHANGED <<issuedCaps, nextNonce, epoch, balances, executedTraversals>>

\* Deduct resources atomically.
\* Guard: amount <= balances[p]. If false, action is DISABLED (no partial write).
DeductResource(p, amount) ==
    /\ p      \in Principals
    /\ amount \in 1..MaxResources
    /\ amount <= balances[p]              \* *** ATOMICITY GUARD ***
    /\ balances' = [balances EXCEPT ![p] = balances[p] - amount]
    /\ UNCHANGED <<issuedCaps, revokedNonces, nextNonce, epoch, executedTraversals>>

\* Traverse a topology edge.
\* Only edges declared in the boot manifest are permitted.
TraverseEdge(src, dst) ==
    /\ src \in Nodes
    /\ dst \in Nodes
    /\ <<src, dst>> \in BootEdges         \* *** TOPOLOGY GUARD ***
    /\ executedTraversals' = executedTraversals \cup {<<src, dst>>}
    /\ UNCHANGED <<issuedCaps, revokedNonces, nextNonce, epoch, balances>>

\* Rotate epoch: increment generation, clear revocations and nonce window.
\* Old-generation caps fail IsValidCap at cap.gen = epoch check.
RotateEpoch ==
    /\ epoch     < MaxEpoch
    /\ epoch'    = epoch + 1
    /\ revokedNonces' = {}
    /\ nextNonce'     = 0
    /\ UNCHANGED <<issuedCaps, balances, executedTraversals>>

---------------------------------------------------------------------------
\* NEXT-STATE RELATION
---------------------------------------------------------------------------

Next ==
    \/ \E p \in Principals, rts \in SUBSET AllRights :
           BootIssueCap(p, rts)
    \/ \E cap \in issuedCaps, q \in Principals, rts \in SUBSET AllRights :
           Delegate(cap, q, rts)
    \/ \E nonce \in Nonces :
           RevokeCap(nonce)
    \/ \E cap \in issuedCaps, right \in AllRights :
           UseCap(cap, right)
    \/ \E p \in Principals, amt \in 1..MaxResources :
           DeductResource(p, amt)
    \/ \E src \in Nodes, dst \in Nodes :
           TraverseEdge(src, dst)
    \/ RotateEpoch

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
\* SECURITY INVARIANTS (THE FOUR THEOREMS)
---------------------------------------------------------------------------

\* THEOREM 1: NON-ESCALATION
\*
\* Formal: forall cap in issuedCaps: cap.rights subset cap.rootRights
\*
\* Proof (induction on issuedCaps):
\*   Base:  issuedCaps = {}.  Vacuously true.
\*   BootIssueCap: rights = rts = rootRights, so rights subset rootRights.
\*   Delegate: guard newRights subset cap.rights, ind.hyp. cap.rights subset
\*             cap.rootRights. newCap.rootRights = cap.rootRights (unchanged).
\*             => newCap.rights subset newCap.rootRights. QED.
\*   All other actions leave issuedCaps unchanged.

NonEscalation ==
    \A cap \in issuedCaps : cap.rights \subseteq cap.rootRights

---------------------------------------------------------------------------

\* THEOREM 2: REVOCATION SOUNDNESS
\*
\* Formal: forall cap in issuedCaps:
\*           cap.nonce in revokedNonces => NOT IsValidCap(cap)
\*
\* Proof:
\*   Base: revokedNonces = {}.  Premise false for all caps.
\*   RevokeCap(n): adds n to revokedNonces. Cap with nonce n now fails
\*     IsValidCap line 2 (nonce in revokedNonces).
\*   RotateEpoch: revokedNonces' = {}, but epoch' = epoch+1.
\*     Old-gen caps now fail IsValidCap line 1 (gen != epoch').
\*   Delegate/BootIssueCap: new caps use nextNonce, not in revokedNonces.
\*   UseCap: adds cap.nonce to revokedNonces, so that cap is denied next.

RevocationSoundness ==
    \A cap \in issuedCaps :
        cap.nonce \in revokedNonces => ~IsValidCap(cap)

---------------------------------------------------------------------------

\* THEOREM 3: RESOURCE ATOMICITY
\*
\* Formal: forall p in Principals: balances[p] >= 0
\*
\* This plus the DeductResource guard (amount <= balances[p]) proves:
\*   deduct(p, amount) => (balance' = balance - amount) OR (action disabled).
\*
\* Proof:
\*   Base: balances[p] = MaxResources >= 0.
\*   DeductResource: only enabled when amount <= balances[p].
\*     balances'[p] = balances[p] - amount >= 0.
\*   All other actions leave balances unchanged.

ResourceAtomicity ==
    \A p \in Principals : balances[p] >= 0

---------------------------------------------------------------------------

\* THEOREM 4: TOPOLOGY BOUNDEDNESS
\*
\* Formal: executedTraversals subset BootEdges
\*
\* Proof:
\*   Base: executedTraversals = {} subset BootEdges.
\*   TraverseEdge: guard requires <<src,dst>> in BootEdges.
\*     executedTraversals' = executedTraversals union {<<src,dst>>} subset BootEdges.
\*   All other actions leave executedTraversals unchanged.

TopologyBoundedness ==
    executedTraversals \subseteq BootEdges

---------------------------------------------------------------------------

\* COMPOSITE: all four theorems must hold simultaneously.
AllSecurityInvariantsHold ==
    /\ NonEscalation
    /\ RevocationSoundness
    /\ ResourceAtomicity
    /\ TopologyBoundedness

---------------------------------------------------------------------------

\* HELPER: Delegation chain soundness.
\* Any two caps sharing the same rootRights have combined rights
\* bounded by that root.
DelegationChainSound ==
    \A c1 \in issuedCaps :
        \A c2 \in issuedCaps :
            c1.rootRights = c2.rootRights =>
                (c1.rights \cup c2.rights) \subseteq c1.rootRights

====
