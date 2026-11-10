(* SPDX-License-Identifier: MPL-2.0 *)
(* SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell *)
(*
   Chain-of-trust soundness: the Rocq leg (re-proved).

   The source of truth is verification/proofs/agda/ChainOfTrust.agda. This file
   restates its definitions and theorems in Rocq and proves them by hand: no
   translator is involved, so the route is `re-proved` (PROOF-POLICY §2). The
   statement-by-statement comparison with the Agda source is recorded in
   verification/proofs/CORRESPONDENCE.adoc.

   Only the Rocq prelude is used: no Require, no Axiom, no Admitted. The final
   `Print Assumptions` lines report each theorem's axioms; they must report
   "Closed under the global context".

   Check with: coqc ChainOfTrust.v
*)

Inductive verdict : Type := secure | insecure | bogus.

Definition check (b : bool) (v : verdict) : verdict :=
  match b with
  | true => v
  | false => bogus
  end.

Section Model.

  Variables Key Data Sig : Type.
  Variable verify : Key -> Data -> Sig -> bool.
  Variable keyData : Key -> Data.

  Inductive link : Type := delegate : Key -> Sig -> link.

  Inductive leaf : Type :=
  | answer : Data -> Sig -> leaf
  | denial : Data -> Sig -> leaf.

  Fixpoint validate (k : Key) (ls : list link) (l : leaf) : verdict :=
    match ls with
    | nil =>
        match l with
        | answer d s => check (verify k d s) secure
        | denial d s => check (verify k d s) insecure
        end
    | cons (delegate c s) rest => check (verify k (keyData c) s) (validate c rest l)
    end.

  Inductive leaf_verified (k : Key) : leaf -> Prop :=
  | answer_ok : forall d s, verify k d s = true -> leaf_verified k (answer d s)
  | denial_ok : forall d s, verify k d s = true -> leaf_verified k (denial d s).

  Inductive verified : Key -> list link -> leaf -> Prop :=
  | here : forall k l, leaf_verified k l -> verified k nil l
  | step : forall k c s ls l,
      verify k (keyData c) s = true -> verified c ls l ->
      verified k (cons (delegate c s) ls) l.

  Inductive is_answer : leaf -> Prop := is_answer_i : forall d s, is_answer (answer d s).
  Inductive is_denial : leaf -> Prop := is_denial_i : forall d s, is_denial (denial d s).

  Definition earned (l : leaf) : verdict :=
    match l with
    | answer _ _ => secure
    | denial _ _ => insecure
    end.

  Lemma check_secure : forall b v, check b v = secure -> b = true /\ v = secure.
  Proof. intros [|] v H; simpl in H; [ split; [reflexivity | exact H] | discriminate H ]. Qed.

  Lemma check_insecure : forall b v, check b v = insecure -> b = true /\ v = insecure.
  Proof. intros [|] v H; simpl in H; [ split; [reflexivity | exact H] | discriminate H ]. Qed.

  Lemma check_pass : forall b v, b = true -> check b v = v.
  Proof. intros b v H; rewrite H; reflexivity. Qed.

  Theorem secure_sound : forall k ls l,
    validate k ls l = secure -> verified k ls l /\ is_answer l.
  Proof.
    intros k ls; revert k; induction ls as [| [c s] ls IH]; intros k l H.
    - destruct l as [d s | d s]; simpl in H.
      + destruct (check_secure _ _ H) as [Hv _].
        split; [ apply here, answer_ok; exact Hv | apply is_answer_i ].
      + destruct (check_secure _ _ H) as [_ Hx]. discriminate Hx.
    - simpl in H. destruct (check_secure _ _ H) as [Hv Hr].
      destruct (IH c l Hr) as [Hc Ha].
      split; [ apply step; assumption | exact Ha ].
  Qed.

  Theorem insecure_sound : forall k ls l,
    validate k ls l = insecure -> verified k ls l /\ is_denial l.
  Proof.
    intros k ls; revert k; induction ls as [| [c s] ls IH]; intros k l H.
    - destruct l as [d s | d s]; simpl in H.
      + destruct (check_insecure _ _ H) as [_ Hx]. discriminate Hx.
      + destruct (check_insecure _ _ H) as [Hv _].
        split; [ apply here, denial_ok; exact Hv | apply is_denial_i ].
    - simpl in H. destruct (check_insecure _ _ H) as [Hv Hr].
      destruct (IH c l Hr) as [Hc Hd].
      split; [ apply step; assumption | exact Hd ].
  Qed.

  Theorem complete : forall k ls l, verified k ls l -> validate k ls l = earned l.
  Proof.
    intros k ls l H; induction H as [k l Hl | k c s ls l Hv Hr IH].
    - destruct Hl as [d s Hv | d s Hv]; simpl; apply check_pass; exact Hv.
    - simpl. rewrite (check_pass _ _ Hv). exact IH.
  Qed.

  Theorem fail_closed : forall k ls l,
    ~ verified k ls l -> validate k ls l = bogus.
  Proof.
    intros k ls l Hn.
    destruct (validate k ls l) eqn:E.
    - exfalso. apply Hn. exact (proj1 (secure_sound k ls l E)).
    - exfalso. apply Hn. exact (proj1 (insecure_sound k ls l E)).
    - reflexivity.
  Qed.

End Model.

Print Assumptions secure_sound.
Print Assumptions insecure_sound.
Print Assumptions complete.
Print Assumptions fail_closed.
