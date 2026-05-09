---------------- MODULE sifr_capability ----------------
(******************************************************************)
(* SIFR v0.3 TLA+ model of the capability authorization state      *)
(* machine.                                                         *)
(*                                                                  *)
(* States evolve as:                                                *)
(*   unissued -> active -> {expired | revoked}                      *)
(*                                                                  *)
(* Within "active", a capability may be consumed up to MaxCalls     *)
(* times, by its bound subject, for actions in its grant, by an     *)
(* unrevoked key bound to that subject's DID.                       *)
(*                                                                  *)
(* This module captures authorization safety only. It does not      *)
(* model cryptography (no Dolev-Yao adversary, no symbolic          *)
(* encryption), liveness, or audit-DAG integrity. Those are         *)
(* tested at the implementation level (see                          *)
(* tests/test_v0_3_adversary.py and tests/test_audit_dag.py).        *)
(******************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Caps,         \* finite set of capability identifiers
    Subs,         \* finite set of subject identifiers
    Issuers,      \* finite set of issuer identifiers
    Acts,         \* finite set of action names
    Msgs,         \* finite set of message identifiers (for replay)
    Kids,         \* finite set of key identifiers
    MaxCalls      \* per-capability call budget

ASSUME
    /\ MaxCalls \in Nat \ {0}
    /\ Caps # {} /\ Subs # {} /\ Issuers # {} /\ Acts # {} /\ Msgs # {} /\ Kids # {}

CapStates == {"unissued", "active", "expired", "revoked"}
UNSET == "_unset_"

VARIABLES
    state,         \* [Caps -> CapStates]
    sub,           \* [Caps -> Subs \cup {UNSET}]
    iss,           \* [Caps -> Issuers \cup {UNSET}]
    grantedActs,   \* [Caps -> SUBSET Acts]
    used,          \* [Caps -> 0..MaxCalls]
    consumedMsg,   \* SUBSET (Subs \X Msgs)  -- replay set
    revokedKids,   \* SUBSET Kids           -- key-level revocation set
    history        \* Seq of records [op, cap, sub, iss, kid, msg, act]

vars == <<state, sub, iss, grantedActs, used, consumedMsg, revokedKids, history>>

TypeInvariant ==
    /\ state \in [Caps -> CapStates]
    /\ sub \in [Caps -> Subs \cup {UNSET}]
    /\ iss \in [Caps -> Issuers \cup {UNSET}]
    /\ grantedActs \in [Caps -> SUBSET Acts]
    /\ used \in [Caps -> 0..MaxCalls]
    /\ consumedMsg \subseteq (Subs \X Msgs)
    /\ revokedKids \subseteq Kids

Init ==
    /\ state = [c \in Caps |-> "unissued"]
    /\ sub = [c \in Caps |-> UNSET]
    /\ iss = [c \in Caps |-> UNSET]
    /\ grantedActs = [c \in Caps |-> {}]
    /\ used = [c \in Caps |-> 0]
    /\ consumedMsg = {}
    /\ revokedKids = {}
    /\ history = << >>

Issue(c, s, i, A) ==
    /\ state[c] = "unissued"
    /\ A \subseteq Acts
    /\ A # {}
    /\ state' = [state EXCEPT ![c] = "active"]
    /\ sub' = [sub EXCEPT ![c] = s]
    /\ iss' = [iss EXCEPT ![c] = i]
    /\ grantedActs' = [grantedActs EXCEPT ![c] = A]
    /\ history' = Append(history, [op |-> "Issue", cap |-> c, sub |-> s, iss |-> i, kid |-> UNSET, msg |-> "_n_a_", act |-> "_n_a_"])
    /\ UNCHANGED <<used, consumedMsg, revokedKids>>

Expire(c) ==
    /\ state[c] = "active"
    /\ state' = [state EXCEPT ![c] = "expired"]
    /\ history' = Append(history, [op |-> "Expire", cap |-> c, sub |-> UNSET, iss |-> UNSET, kid |-> UNSET, msg |-> "_n_a_", act |-> "_n_a_"])
    /\ UNCHANGED <<sub, iss, grantedActs, used, consumedMsg, revokedKids>>

Revoke(c) ==
    /\ state[c] = "active"
    /\ state' = [state EXCEPT ![c] = "revoked"]
    /\ history' = Append(history, [op |-> "Revoke", cap |-> c, sub |-> UNSET, iss |-> UNSET, kid |-> UNSET, msg |-> "_n_a_", act |-> "_n_a_"])
    /\ UNCHANGED <<sub, iss, grantedActs, used, consumedMsg, revokedKids>>

RevokeKey(k) ==
    /\ k \notin revokedKids
    /\ revokedKids' = revokedKids \cup {k}
    /\ history' = Append(history, [op |-> "RevokeKey", cap |-> CHOOSE c \in Caps : TRUE, sub |-> UNSET, iss |-> UNSET, kid |-> k, msg |-> "_n_a_", act |-> "_n_a_"])
    /\ UNCHANGED <<state, sub, iss, grantedActs, used, consumedMsg>>

Consume(c, s, i, k, a, m) ==
    /\ state[c] = "active"
    /\ sub[c] = s
    /\ iss[c] = i
    /\ k \notin revokedKids
    /\ a \in grantedActs[c]
    /\ used[c] < MaxCalls
    /\ <<s, m>> \notin consumedMsg
    /\ used' = [used EXCEPT ![c] = used[c] + 1]
    /\ consumedMsg' = consumedMsg \cup {<<s, m>>}
    /\ history' = Append(history, [op |-> "Consume", cap |-> c, sub |-> s, iss |-> i, kid |-> k, msg |-> m, act |-> a])
    /\ UNCHANGED <<state, sub, iss, grantedActs, revokedKids>>

Next ==
    \/ \E c \in Caps, s \in Subs, i \in Issuers, A \in (SUBSET Acts) \ {{}}: Issue(c, s, i, A)
    \/ \E c \in Caps: Expire(c)
    \/ \E c \in Caps: Revoke(c)
    \/ \E k \in Kids: RevokeKey(k)
    \/ \E c \in Caps, s \in Subs, i \in Issuers, k \in Kids, a \in Acts, m \in Msgs: Consume(c, s, i, k, a, m)

Spec == Init /\ [][Next]_vars

(*================ INVARIANTS ================*)

\* I1 UnauthorizedActionNeverAllowed
NoUnauthorizedActionConsume ==
    \A x \in 1..Len(history):
        history[x].op = "Consume" =>
            history[x].act \in grantedActs[history[x].cap]

\* I2 WrongSubjectNeverAllowed
NoWrongSubjectConsume ==
    \A x \in 1..Len(history):
        history[x].op = "Consume" =>
            history[x].sub = sub[history[x].cap]

\* I3 ExpiredGrantNeverAllowed
NoConsumeAfterExpire ==
    \A x, y \in 1..Len(history):
        (history[x].op = "Expire" /\ history[y].op = "Consume" /\
         history[x].cap = history[y].cap /\ x < y) => FALSE

\* I4 RevokedGrantNeverAllowed
NoConsumeAfterRevoke ==
    \A x, y \in 1..Len(history):
        (history[x].op = "Revoke" /\ history[y].op = "Consume" /\
         history[x].cap = history[y].cap /\ x < y) => FALSE

\* I5 OverBudgetNeverAllowed
NoOverBudgetConsume ==
    \A c \in Caps: used[c] <= MaxCalls

\* I6 ReplayNeverAllowed
NoReplayedConsume ==
    \A x, y \in 1..Len(history):
        (x # y /\
         history[x].op = "Consume" /\ history[y].op = "Consume" /\
         history[x].sub = history[y].sub /\
         history[x].msg = history[y].msg) => FALSE

\* I8 WrongIssuerNeverAllowed
\*    Every consume must reference the issuer the cap was issued under.
NoConsumeWithWrongIssuer ==
    \A x \in 1..Len(history):
        history[x].op = "Consume" =>
            history[x].iss = iss[history[x].cap]

\* I9 RevokedKeyNeverAllowed
\*    Every consume's kid must not be in the revokedKids set at consume time.
\*    Since RevokeKey is monotone (only adds), if a kid is currently in
\*    revokedKids it was either never used or used before revocation. We
\*    check the structural form: no Consume is ever recorded for a kid that
\*    was already revoked at the time the action fired. The Consume guard
\*    enforces this directly; the invariant double-checks via history scan.
NoConsumeWithRevokedKey ==
    \A x, y \in 1..Len(history):
        (history[x].op = "RevokeKey" /\ history[y].op = "Consume" /\
         history[x].kid = history[y].kid /\ x < y) => FALSE

\* Note on I7 (TamperedCredentialNeverAllowed) and I10 (AuditTamperDetected):
\* These invariants are enforced at the byte/cryptography layer, not at the
\* state-machine layer. They are tested at the implementation level by
\* tests/test_credentials.py (mutation-after-sign rejection) and
\* tests/test_audit_dag.py (CID recomputation on stored mutation), and by
\* tests/test_v0_3_adversary.py::test_a05/06/07 and ::test_a21. They are NOT
\* in the TLA+ proof obligation set because the model abstracts away wire
\* bytes by design.

SecureCapabilityLifecycle ==
    /\ TypeInvariant
    /\ NoUnauthorizedActionConsume
    /\ NoWrongSubjectConsume
    /\ NoConsumeAfterExpire
    /\ NoConsumeAfterRevoke
    /\ NoOverBudgetConsume
    /\ NoReplayedConsume
    /\ NoConsumeWithWrongIssuer
    /\ NoConsumeWithRevokedKey

================================================================
