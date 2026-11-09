-- SPDX-License-Identifier: MPL-2.0
-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
--
-- Chain-of-trust soundness: the Lean leg (re-proved).
--
-- The source of truth is verification/proofs/agda/ChainOfTrust.agda. This file
-- restates its definitions and theorems in Lean 4 and proves them by hand. No
-- translator is involved, so the route is `re-proved` (PROOF-POLICY §2). The
-- statement-by-statement comparison with the Agda source is recorded in
-- verification/proofs/CORRESPONDENCE.adoc.
--
-- Core Lean only: no imports, no Mathlib (PROOF-POLICY §2), no `axiom`, no
-- `sorry`. The `#print axioms` lines at the end must each report that the
-- theorem "does not depend on any axioms".
--
-- Check with: lean ChainOfTrust.lean   (toolchain: ./lean-toolchain)

namespace ChainOfTrust

inductive Verdict where
  | secure | insecure | bogus
  deriving DecidableEq

def check : Bool → Verdict → Verdict
  | true,  v => v
  | false, _ => .bogus

section Model

variable {Key Data Sig : Type} (verify : Key → Data → Sig → Bool) (keyData : Key → Data)

inductive Link (Key Sig : Type) where
  | delegate : Key → Sig → Link Key Sig

inductive Leaf (Data Sig : Type) where
  | answer : Data → Sig → Leaf Data Sig
  | denial : Data → Sig → Leaf Data Sig

def validate : Key → List (Link Key Sig) → Leaf Data Sig → Verdict
  | k, [],                  .answer d s => check (verify k d s) .secure
  | k, [],                  .denial d s => check (verify k d s) .insecure
  | k, .delegate c s :: ls, l          => check (verify k (keyData c) s) (validate c ls l)

inductive LeafVerified (k : Key) : Leaf Data Sig → Prop where
  | answer_ok {d : Data} {s : Sig} : verify k d s = true → LeafVerified k (.answer d s)
  | denial_ok {d : Data} {s : Sig} : verify k d s = true → LeafVerified k (.denial d s)

inductive Verified : Key → List (Link Key Sig) → Leaf Data Sig → Prop where
  | here {k : Key} {l : Leaf Data Sig} : LeafVerified verify k l → Verified k [] l
  | step {k c : Key} {s : Sig} {ls : List (Link Key Sig)} {l : Leaf Data Sig} :
      verify k (keyData c) s = true → Verified c ls l → Verified k (.delegate c s :: ls) l

inductive IsAnswer : Leaf Data Sig → Prop where
  | is_answer {d : Data} {s : Sig} : IsAnswer (.answer d s)

inductive IsDenial : Leaf Data Sig → Prop where
  | is_denial {d : Data} {s : Sig} : IsDenial (.denial d s)

def earned : Leaf Data Sig → Verdict
  | .answer _ _ => .secure
  | .denial _ _ => .insecure

theorem check_secure : ∀ (b : Bool) (v : Verdict), check b v = .secure → b = true ∧ v = .secure
  | true,  _, h => ⟨rfl, h⟩
  | false, _, h => nomatch h

theorem check_insecure : ∀ (b : Bool) (v : Verdict), check b v = .insecure → b = true ∧ v = .insecure
  | true,  _, h => ⟨rfl, h⟩
  | false, _, h => nomatch h

theorem check_pass : ∀ {b : Bool} (v : Verdict), b = true → check b v = v
  | _, _, rfl => rfl

theorem secure_sound : ∀ (k : Key) (ls : List (Link Key Sig)) (l : Leaf Data Sig),
    validate verify keyData k ls l = .secure →
    Verified verify keyData k ls l ∧ IsAnswer l
  | k, [], .answer d s, h =>
      ⟨.here (.answer_ok (check_secure (verify k d s) .secure h).1), .is_answer⟩
  | k, [], .denial d s, h => nomatch (check_secure (verify k d s) .insecure h).2
  | k, .delegate c s :: ls, l, h =>
      have r := check_secure (verify k (keyData c) s) (validate verify keyData c ls l) h
      have rest := secure_sound c ls l r.2
      ⟨.step r.1 rest.1, rest.2⟩

theorem insecure_sound : ∀ (k : Key) (ls : List (Link Key Sig)) (l : Leaf Data Sig),
    validate verify keyData k ls l = .insecure →
    Verified verify keyData k ls l ∧ IsDenial l
  | k, [], .answer d s, h => nomatch (check_insecure (verify k d s) .secure h).2
  | k, [], .denial d s, h =>
      ⟨.here (.denial_ok (check_insecure (verify k d s) .insecure h).1), .is_denial⟩
  | k, .delegate c s :: ls, l, h =>
      have r := check_insecure (verify k (keyData c) s) (validate verify keyData c ls l) h
      have rest := insecure_sound c ls l r.2
      ⟨.step r.1 rest.1, rest.2⟩

theorem complete : ∀ {k : Key} {ls : List (Link Key Sig)} {l : Leaf Data Sig},
    Verified verify keyData k ls l → validate verify keyData k ls l = earned l
  | _, _, _, .here (.answer_ok p) => check_pass .secure p
  | _, _, _, .here (.denial_ok p) => check_pass .insecure p
  | _, _, _, .step (c := c) (ls := ls) (l := l) p rest =>
      (check_pass (validate verify keyData c ls l) p).trans (complete rest)

theorem fail_closed : ∀ (k : Key) (ls : List (Link Key Sig)) (l : Leaf Data Sig),
    ¬ Verified verify keyData k ls l → validate verify keyData k ls l = .bogus := by
  intro k ls l hn
  cases e : validate verify keyData k ls l with
  | secure   => exact absurd (secure_sound verify keyData k ls l e).1 hn
  | insecure => exact absurd (insecure_sound verify keyData k ls l e).1 hn
  | bogus    => rfl

end Model

end ChainOfTrust

#print axioms ChainOfTrust.secure_sound
#print axioms ChainOfTrust.insecure_sound
#print axioms ChainOfTrust.complete
#print axioms ChainOfTrust.fail_closed
