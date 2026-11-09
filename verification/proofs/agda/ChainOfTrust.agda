{-# OPTIONS --safe --without-K --cubical-compatible #-}
-- SPDX-License-Identifier: MPL-2.0
-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
--
-- Chain-of-trust soundness for a DNSSEC validator, as theory.
--
-- The statement is about the decision procedure, not about zig-dnssec's
-- code: it holds for any validator that walks a chain of signed keys down
-- from a trust anchor and decides on the last link the way `validate` does.
-- That makes it theory under PROOF-POLICY §1, so Agda is its source of truth
-- and it is re-proved in Rocq (verification/proofs/coq/ChainOfTrust.v) and in
-- Lean (verification/proofs/lean4/ChainOfTrust.lean). How the three
-- statements correspond is recorded in verification/proofs/CORRESPONDENCE.adoc.
--
-- The module is self-contained: no standard library, no postulates, so its
-- import cone is this file and Agda's primitives. The cryptography is a
-- module parameter, not an assumption smuggled in: `verify` is whatever the
-- signature check is, and every theorem below holds for every `verify`.
--
-- What the theorems say, in words:
--
--   secure-sound    A `secure` verdict means every key on the path from the
--                   anchor was signed by the key above it, and the answer was
--                   signed by the last key.
--   insecure-sound  An `insecure` verdict means the same chain, ending in a
--                   *verified* proof that the next delegation is unsigned.
--   complete        A fully verified chain is accepted: `secure` for an
--                   answer, `insecure` for a denial.
--   fail-closed     A chain that is not fully verified is `bogus`: a failure
--                   can never come out as `secure` or `insecure`.
--
-- Not in this model (each is a separate row in docs/status/PROOF-STATUS.adoc):
-- choosing the closest trust anchor, NSEC/NSEC3 denial semantics, wildcard
-- expansion, validity windows, and that zig-dnssec's validator.zig follows
-- this procedure.

module ChainOfTrust where

------------------------------------------------------------------------------
-- Prelude: just what the theorems need.

data Bool : Set where
  false true : Bool

data _≡_ {A : Set} (x : A) : A → Set where
  refl : x ≡ x

infix 4 _≡_

trans : {A : Set} {x y z : A} → x ≡ y → y ≡ z → x ≡ z
trans refl q = q

data ⊥ : Set where

⊥-elim : {A : Set} → ⊥ → A
⊥-elim ()

¬_ : Set → Set
¬ A = A → ⊥

data List (A : Set) : Set where
  []  : List A
  _∷_ : A → List A → List A

infixr 5 _∷_

record _×_ (A B : Set) : Set where
  constructor _,_
  field
    fst : A
    snd : B

open _×_

------------------------------------------------------------------------------
-- Verdicts

data Verdict : Set where
  secure insecure bogus : Verdict

-- A step that passed keeps the verdict computed below it; a step that failed
-- is bogus, whatever is below it.
check : Bool → Verdict → Verdict
check true  v = v
check false _ = bogus

------------------------------------------------------------------------------
-- The model, for any keys, signed data, signatures and signature check.

module Model
  (Key Data Sig : Set)
  (verify  : Key → Data → Sig → Bool)   -- the signature check
  (keyData : Key → Data)                -- a key as data another key signs
  where

  -- One delegation step: the current key signs the child zone's key.
  data Link : Set where
    delegate : Key → Sig → Link

  -- What the last key signs: the answer, or a proof that the next delegation
  -- is unsigned.
  data Leaf : Set where
    answer : Data → Sig → Leaf
    denial : Data → Sig → Leaf

  -- The decision procedure, started from a trust anchor's key.
  validate : Key → List Link → Leaf → Verdict
  validate k []                   (answer d s) = check (verify k d s) secure
  validate k []                   (denial d s) = check (verify k d s) insecure
  validate k (delegate c s ∷ ls)  l            = check (verify k (keyData c) s) (validate c ls l)

  -- What a fully verified chain is: every signature on the path checks.
  data LeafVerified (k : Key) : Leaf → Set where
    answer-ok : {d : Data} {s : Sig} → verify k d s ≡ true → LeafVerified k (answer d s)
    denial-ok : {d : Data} {s : Sig} → verify k d s ≡ true → LeafVerified k (denial d s)

  data Verified : Key → List Link → Leaf → Set where
    here : {k : Key} {l : Leaf} → LeafVerified k l → Verified k [] l
    step : {k c : Key} {s : Sig} {ls : List Link} {l : Leaf} →
           verify k (keyData c) s ≡ true → Verified c ls l →
           Verified k (delegate c s ∷ ls) l

  data IsAnswer : Leaf → Set where
    is-answer : {d : Data} {s : Sig} → IsAnswer (answer d s)

  data IsDenial : Leaf → Set where
    is-denial : {d : Data} {s : Sig} → IsDenial (denial d s)

  -- The verdict a fully verified chain earns.
  earned : Leaf → Verdict
  earned (answer _ _) = secure
  earned (denial _ _) = insecure

  ----------------------------------------------------------------------------
  -- Lemmas about `check`

  check-secure : (b : Bool) (v : Verdict) → check b v ≡ secure → (b ≡ true) × (v ≡ secure)
  check-secure true  v p = refl , p
  check-secure false v ()

  check-insecure : (b : Bool) (v : Verdict) → check b v ≡ insecure → (b ≡ true) × (v ≡ insecure)
  check-insecure true  v p = refl , p
  check-insecure false v ()

  check-pass : {b : Bool} (v : Verdict) → b ≡ true → check b v ≡ v
  check-pass v refl = refl

  ----------------------------------------------------------------------------
  -- Theorems

  secure-sound : (k : Key) (ls : List Link) (l : Leaf) →
                 validate k ls l ≡ secure → Verified k ls l × IsAnswer l
  secure-sound k [] (answer d s) p = here (answer-ok (fst (check-secure (verify k d s) secure p))) , is-answer
  secure-sound k [] (denial d s) p with snd (check-secure (verify k d s) insecure p)
  ... | ()
  secure-sound k (delegate c s ∷ ls) l p =
    let r    = check-secure (verify k (keyData c) s) (validate c ls l) p
        rest = secure-sound c ls l (snd r)
    in step (fst r) (fst rest) , snd rest

  insecure-sound : (k : Key) (ls : List Link) (l : Leaf) →
                   validate k ls l ≡ insecure → Verified k ls l × IsDenial l
  insecure-sound k [] (answer d s) p with snd (check-insecure (verify k d s) secure p)
  ... | ()
  insecure-sound k [] (denial d s) p = here (denial-ok (fst (check-insecure (verify k d s) insecure p))) , is-denial
  insecure-sound k (delegate c s ∷ ls) l p =
    let r    = check-insecure (verify k (keyData c) s) (validate c ls l) p
        rest = insecure-sound c ls l (snd r)
    in step (fst r) (fst rest) , snd rest

  complete : {k : Key} {ls : List Link} {l : Leaf} →
             Verified k ls l → validate k ls l ≡ earned l
  complete (here (answer-ok p)) = check-pass secure p
  complete (here (denial-ok p)) = check-pass insecure p
  complete (step {c = c} {ls = ls} {l = l} p rest) =
    trans (check-pass (validate c ls l) p) (complete rest)

  fail-closed : (k : Key) (ls : List Link) (l : Leaf) →
                ¬ Verified k ls l → validate k ls l ≡ bogus
  fail-closed k ls l nv = go (validate k ls l) refl
    where
      go : (v : Verdict) → validate k ls l ≡ v → validate k ls l ≡ bogus
      go secure   eq = ⊥-elim (nv (fst (secure-sound k ls l eq)))
      go insecure eq = ⊥-elim (nv (fst (insecure-sound k ls l eq)))
      go bogus    eq = eq
