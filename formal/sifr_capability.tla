---------------- MODULE sifr_capability ----------------
(******************************************************************)
(* TLA+ model of the SIFR capability lifecycle.                    *)
(*                                                                  *)
(* Capability states evolve as:                                     *)
(*   unissued -> active -> {expired | revoked}                      *)
(* Within "active", a capability may be consumed up to MaxCalls     *)
(* times by its bound subject for actions in its grant.             *)
(*                                                                  *)
(* Precondition guards on Consume encode the SIFR authorization     *)
(* layer: state must be "active", subject must match, action must   *)
(* be granted, budget must remain, and the (subject, message_id)    *)
(* pair must not already have been consumed.                        *)
(*                                                                  *)
(* The invariants in this module + MC.cfg encode the section 1.9    *)
(* properties of docs/full_security_implementation_prompt.md.       *)
(*                                                                  *)
(* This model intentionally does NOT model cryptography. It models  *)
(* the state machine that the v0.2 implementation enforces in       *)
(* sifr/capabilities.py and sifr/replay.py.                          *)
(******************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Caps,         \* finite set of capability identifiers
    Subs,         \* finite set of subject identifiers
    Acts,         \* finite set of action names
    Msgs,         \* finite set of message identifiers (for replay)
    MaxCalls      \* per-capability call budget

ASSUME
    /\ MaxCalls \in Nat \ {0}
    /\ Caps # {}
    /\ Subs # {}
    /\ Acts # {}
    /\ Msgs # {}

CapStates == {"unissued", "active", "expired", "revoked"}
UNSET == "_unset_"

VARIABLES
    state,        \* [Caps -> CapStates]
    sub,          \* [Caps -> Subs \cup {UNSET}]
    grantedActs,  \* [Caps -> SUBSET Acts]
    used,         \* [Caps -> 0..MaxCalls]
    consumedMsg,  \* SUBSET (Subs \X Msgs) -- replay set
    history       \* Seq of records [op, cap, sub, msg, act]

vars == <<state, sub, grantedActs, used, consumedMsg, history>>

TypeInvariant ==
    /\ state \in [Caps -> CapStates]
    /\ sub \in [Caps -> Subs \cup {UNSET}]
    /\ grantedActs \in [Caps -> SUBSET Acts]
    /\ used \in [Caps -> 0..MaxCalls]
    /\ consumedMsg \subseteq (Subs \X Msgs)

Init ==
    /\ state = [c \in Caps |-> "unissued"]
    /\ sub = [c \in Caps |-> UNSET]
    /\ grantedActs = [c \in Caps |-> {}]
    /\ used = [c \in Caps |-> 0]
    /\ consumedMsg = {}
    /\ history = << >>

Issue(c, s, A) ==
    /\ state[c] = "unissued"
    /\ A \subseteq Acts
    /\ A # {}
    /\ state' = [state EXCEPT ![c] = "active"]
    /\ sub' = [sub EXCEPT ![c] = s]
    /\ grantedActs' = [grantedActs EXCEPT ![c] = A]
    /\ history' = Append(history, [op |-> "Issue", cap |-> c, sub |-> s, msg |-> "_n_a_", act |-> "_n_a_"])
    /\ UNCHANGED <<used, consumedMsg>>

Expire(c) ==
    /\ state[c] = "active"
    /\ state' = [state EXCEPT ![c] = "expired"]
    /\ history' = Append(history, [op |-> "Expire", cap |-> c, sub |-> UNSET, msg |-> "_n_a_", act |-> "_n_a_"])
    /\ UNCHANGED <<sub, grantedActs, used, consumedMsg>>

Revoke(c) ==
    /\ state[c] = "active"
    /\ state' = [state EXCEPT ![c] = "revoked"]
    /\ history' = Append(history, [op |-> "Revoke", cap |-> c, sub |-> UNSET, msg |-> "_n_a_", act |-> "_n_a_"])
    /\ UNCHANGED <<sub, grantedActs, used, consumedMsg>>

Consume(c, s, a, m) ==
    /\ state[c] = "active"
    /\ sub[c] = s
    /\ a \in grantedActs[c]
    /\ used[c] < MaxCalls
    /\ <<s, m>> \notin consumedMsg
    /\ used' = [used EXCEPT ![c] = used[c] + 1]
    /\ consumedMsg' = consumedMsg \cup {<<s, m>>}
    /\ history' = Append(history, [op |-> "Consume", cap |-> c, sub |-> s, msg |-> m, act |-> a])
    /\ UNCHANGED <<state, sub, grantedActs>>

Next ==
    \/ \E c \in Caps, s \in Subs, A \in (SUBSET Acts) \ {{}}: Issue(c, s, A)
    \/ \E c \in Caps: Expire(c)
    \/ \E c \in Caps: Revoke(c)
    \/ \E c \in Caps, s \in Subs, a \in Acts, m \in Msgs: Consume(c, s, a, m)

Spec == Init /\ [][Next]_vars

(*================ INVARIANTS ================*)

\* I1: budget never exceeded.
NoOverBudgetConsume ==
    \A c \in Caps: used[c] <= MaxCalls

\* I2: every consume in history has the matching bound subject.
NoWrongSubjectConsume ==
    \A i \in 1..Len(history):
        history[i].op = "Consume" =>
            history[i].sub = sub[history[i].cap]

\* I3: every consume used an action in the cap's grant.
NoUnauthorizedActionConsume ==
    \A i \in 1..Len(history):
        history[i].op = "Consume" =>
            history[i].act \in grantedActs[history[i].cap]

\* I4: no two consumes share the same (sub, msg). Replay protection.
NoReplayedConsume ==
    \A i, j \in 1..Len(history):
        (i # j /\
         history[i].op = "Consume" /\ history[j].op = "Consume" /\
         history[i].sub = history[j].sub /\
         history[i].msg = history[j].msg) => FALSE

\* I5: a Consume never occurs at a history index after a Revoke for the same cap.
NoConsumeAfterRevoke ==
    \A i, j \in 1..Len(history):
        (history[i].op = "Revoke" /\ history[j].op = "Consume" /\
         history[i].cap = history[j].cap /\ i < j) => FALSE

\* I6: a Consume never occurs at a history index after an Expire for the same cap.
NoConsumeAfterExpire ==
    \A i, j \in 1..Len(history):
        (history[i].op = "Expire" /\ history[j].op = "Consume" /\
         history[i].cap = history[j].cap /\ i < j) => FALSE

(* Combined safety property (conjunction). *)
SecureCapabilityLifecycle ==
    /\ NoOverBudgetConsume
    /\ NoWrongSubjectConsume
    /\ NoUnauthorizedActionConsume
    /\ NoReplayedConsume
    /\ NoConsumeAfterRevoke
    /\ NoConsumeAfterExpire

================================================================
