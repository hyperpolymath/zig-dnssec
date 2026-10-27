-- SPDX-License-Identifier: MPL-2.0
-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
||| zig-dnssec ABI, version 1: the codes of the C interface and what a verdict
||| permits, as types.
|||
||| The contract is src/interface/ffi/include/zig_dnssec.h. Every code below is
||| compared with the header's macros by `zig build test`
||| (src/interface/ffi/test/seam_test.zig), so the two cannot drift silently.
|||
||| The central rule of the seam, stated here as a type rather than a comment:
||| answer data exists only with a SECURE verdict (authenticated to a trust
||| anchor) or an INSECURE one (proven unsigned, or allowed by an explicit
||| policy). A BOGUS or INDETERMINATE outcome has no field that could hold an
||| answer. In the estate's epistemic vocabulary, SECURE is knowledge, INSECURE
||| is justified absence of authentication, and BOGUS and INDETERMINATE are
||| failures that must not be mistaken for either.

module Abi.Types

%default total

--------------------------------------------------------------------------------
-- Call status
--------------------------------------------------------------------------------

||| ZIG_DNSSEC_OK and ZIG_DNSSEC_ERR_*
public export
data Status
  = Ok
  | InvalidArgument
  | OutOfMemory
  | BadAnchors
  | BadName
  | BadTrace
  | QueryFailed
  | BufferTooSmall

public export
statusCode : Status -> Int
statusCode Ok = 0
statusCode InvalidArgument = 1
statusCode OutOfMemory = 2
statusCode BadAnchors = 3
statusCode BadName = 4
statusCode BadTrace = 5
statusCode QueryFailed = 6
statusCode BufferTooSmall = 7

public export
statusFromCode : Int -> Maybe Status
statusFromCode 0 = Just Ok
statusFromCode 1 = Just InvalidArgument
statusFromCode 2 = Just OutOfMemory
statusFromCode 3 = Just BadAnchors
statusFromCode 4 = Just BadName
statusFromCode 5 = Just BadTrace
statusFromCode 6 = Just QueryFailed
statusFromCode 7 = Just BufferTooSmall
statusFromCode _ = Nothing

export
statusRoundTrip : (s : Status) -> statusFromCode (statusCode s) = Just s
statusRoundTrip Ok = Refl
statusRoundTrip InvalidArgument = Refl
statusRoundTrip OutOfMemory = Refl
statusRoundTrip BadAnchors = Refl
statusRoundTrip BadName = Refl
statusRoundTrip BadTrace = Refl
statusRoundTrip QueryFailed = Refl
statusRoundTrip BufferTooSmall = Refl

public export
Show Status where
  show Ok = "ok"
  show InvalidArgument = "invalid_argument"
  show OutOfMemory = "out_of_memory"
  show BadAnchors = "bad_anchors"
  show BadName = "bad_name"
  show BadTrace = "bad_trace"
  show QueryFailed = "query_failed"
  show BufferTooSmall = "buffer_too_small"

--------------------------------------------------------------------------------
-- Security
--------------------------------------------------------------------------------

||| ZIG_DNSSEC_SECURITY_*, without NONE: NONE is the absence of a verdict and
||| has no constructor here.
public export
data Security = Secure | Insecure | Bogus | Indeterminate

public export
securityCode : Security -> Bits8
securityCode Secure = 1
securityCode Insecure = 2
securityCode Bogus = 3
securityCode Indeterminate = 4

public export
securityFromCode : Bits8 -> Maybe Security
securityFromCode 1 = Just Secure
securityFromCode 2 = Just Insecure
securityFromCode 3 = Just Bogus
securityFromCode 4 = Just Indeterminate
securityFromCode _ = Nothing

export
securityRoundTrip : (s : Security) -> securityFromCode (securityCode s) = Just s
securityRoundTrip Secure = Refl
securityRoundTrip Insecure = Refl
securityRoundTrip Bogus = Refl
securityRoundTrip Indeterminate = Refl

||| A zeroed verdict (ZIG_DNSSEC_SECURITY_NONE) decodes to no verdict at all,
||| never to Secure.
export
zeroIsNoVerdict : securityFromCode 0 = Nothing
zeroIsNoVerdict = Refl

public export
Show Security where
  show Secure = "secure"
  show Insecure = "insecure"
  show Bogus = "bogus"
  show Indeterminate = "indeterminate"

--------------------------------------------------------------------------------
-- What a verdict permits
--------------------------------------------------------------------------------

||| Evidence that a verdict permits using its answer.
public export
data Usable : Security -> Type where
  UsableSecure : Usable Secure
  UsableInsecure : Usable Insecure

export
Uninhabited (Usable Bogus) where
  uninhabited x impossible

export
Uninhabited (Usable Indeterminate) where
  uninhabited x impossible

public export
usable : (s : Security) -> Dec (Usable s)
usable Secure = Yes UsableSecure
usable Insecure = Yes UsableInsecure
usable Bogus = No absurd
usable Indeterminate = No absurd

||| The answer a verdict can carry: text for Secure and Insecure, nothing
||| (the unit type) for Bogus and Indeterminate.
public export
AnswerFor : Security -> Type
AnswerFor Secure = String
AnswerFor Insecure = String
AnswerFor Bogus = ()
AnswerFor Indeterminate = ()

||| Only a usable verdict carries an answer.
export
answerOnlyIfUsable : (s : Security) -> Not (Usable s) -> AnswerFor s = ()
answerOnlyIfUsable Secure no = absurd (no UsableSecure)
answerOnlyIfUsable Insecure no = absurd (no UsableInsecure)
answerOnlyIfUsable Bogus _ = Refl
answerOnlyIfUsable Indeterminate _ = Refl

--------------------------------------------------------------------------------
-- Reasons
--------------------------------------------------------------------------------

||| ZIG_DNSSEC_REASON_* (NONE is the absence of a reason). Names follow the
||| validator's `Reason` enum: InsecureDelegation is insecure_delegation.
public export
data Reason
  -- insecure
  = InsecureDelegation
  | Nsec3OptOut
  | UnsupportedAlgorithmPolicy
  | Nsec3IterationsPolicy
  -- bogus
  | SignatureInvalid
  | SignatureExpired
  | SignatureNotYetValid
  | SignatureBadPeriod
  | NoMatchingKey
  | NoSupportedSignature
  | MissingSignature
  | DnskeyMissing
  | DnskeyNotAuthenticated
  | DsNotAuthenticated
  | BadSigner
  | DenialFailed
  | DenialMissing
  | Nsec3InconsistentParams
  | UnsupportedAlgorithm
  | Nsec3IterationsExceeded
  | ResourceLimit
  | CnameLoop
  | DnameMismatch
  | MalformedResponse
  | ChainLoop
  -- indeterminate
  | NoTrustAnchor
  | FetchFailed
  | UpstreamRcode
  | Truncated

public export
reasonCode : Reason -> Bits8
reasonCode InsecureDelegation = 1
reasonCode Nsec3OptOut = 2
reasonCode UnsupportedAlgorithmPolicy = 3
reasonCode Nsec3IterationsPolicy = 4
reasonCode SignatureInvalid = 5
reasonCode SignatureExpired = 6
reasonCode SignatureNotYetValid = 7
reasonCode SignatureBadPeriod = 8
reasonCode NoMatchingKey = 9
reasonCode NoSupportedSignature = 10
reasonCode MissingSignature = 11
reasonCode DnskeyMissing = 12
reasonCode DnskeyNotAuthenticated = 13
reasonCode DsNotAuthenticated = 14
reasonCode BadSigner = 15
reasonCode DenialFailed = 16
reasonCode DenialMissing = 17
reasonCode Nsec3InconsistentParams = 18
reasonCode UnsupportedAlgorithm = 19
reasonCode Nsec3IterationsExceeded = 20
reasonCode ResourceLimit = 21
reasonCode CnameLoop = 22
reasonCode DnameMismatch = 23
reasonCode MalformedResponse = 24
reasonCode ChainLoop = 25
reasonCode NoTrustAnchor = 26
reasonCode FetchFailed = 27
reasonCode UpstreamRcode = 28
reasonCode Truncated = 29

public export
reasonFromCode : Bits8 -> Maybe Reason
reasonFromCode 1 = Just InsecureDelegation
reasonFromCode 2 = Just Nsec3OptOut
reasonFromCode 3 = Just UnsupportedAlgorithmPolicy
reasonFromCode 4 = Just Nsec3IterationsPolicy
reasonFromCode 5 = Just SignatureInvalid
reasonFromCode 6 = Just SignatureExpired
reasonFromCode 7 = Just SignatureNotYetValid
reasonFromCode 8 = Just SignatureBadPeriod
reasonFromCode 9 = Just NoMatchingKey
reasonFromCode 10 = Just NoSupportedSignature
reasonFromCode 11 = Just MissingSignature
reasonFromCode 12 = Just DnskeyMissing
reasonFromCode 13 = Just DnskeyNotAuthenticated
reasonFromCode 14 = Just DsNotAuthenticated
reasonFromCode 15 = Just BadSigner
reasonFromCode 16 = Just DenialFailed
reasonFromCode 17 = Just DenialMissing
reasonFromCode 18 = Just Nsec3InconsistentParams
reasonFromCode 19 = Just UnsupportedAlgorithm
reasonFromCode 20 = Just Nsec3IterationsExceeded
reasonFromCode 21 = Just ResourceLimit
reasonFromCode 22 = Just CnameLoop
reasonFromCode 23 = Just DnameMismatch
reasonFromCode 24 = Just MalformedResponse
reasonFromCode 25 = Just ChainLoop
reasonFromCode 26 = Just NoTrustAnchor
reasonFromCode 27 = Just FetchFailed
reasonFromCode 28 = Just UpstreamRcode
reasonFromCode 29 = Just Truncated
reasonFromCode _ = Nothing

export
reasonRoundTrip : (r : Reason) -> reasonFromCode (reasonCode r) = Just r
reasonRoundTrip InsecureDelegation = Refl
reasonRoundTrip Nsec3OptOut = Refl
reasonRoundTrip UnsupportedAlgorithmPolicy = Refl
reasonRoundTrip Nsec3IterationsPolicy = Refl
reasonRoundTrip SignatureInvalid = Refl
reasonRoundTrip SignatureExpired = Refl
reasonRoundTrip SignatureNotYetValid = Refl
reasonRoundTrip SignatureBadPeriod = Refl
reasonRoundTrip NoMatchingKey = Refl
reasonRoundTrip NoSupportedSignature = Refl
reasonRoundTrip MissingSignature = Refl
reasonRoundTrip DnskeyMissing = Refl
reasonRoundTrip DnskeyNotAuthenticated = Refl
reasonRoundTrip DsNotAuthenticated = Refl
reasonRoundTrip BadSigner = Refl
reasonRoundTrip DenialFailed = Refl
reasonRoundTrip DenialMissing = Refl
reasonRoundTrip Nsec3InconsistentParams = Refl
reasonRoundTrip UnsupportedAlgorithm = Refl
reasonRoundTrip Nsec3IterationsExceeded = Refl
reasonRoundTrip ResourceLimit = Refl
reasonRoundTrip CnameLoop = Refl
reasonRoundTrip DnameMismatch = Refl
reasonRoundTrip MalformedResponse = Refl
reasonRoundTrip ChainLoop = Refl
reasonRoundTrip NoTrustAnchor = Refl
reasonRoundTrip FetchFailed = Refl
reasonRoundTrip UpstreamRcode = Refl
reasonRoundTrip Truncated = Refl

--------------------------------------------------------------------------------
-- Policy flags
--------------------------------------------------------------------------------

||| ZIG_DNSSEC_POLICY_*; the empty list is the library's fail-closed default.
public export
data PolicyFlag = UnsupportedInsecure | IterationsInsecure | NoSha1

public export
policyBit : PolicyFlag -> Bits32
policyBit UnsupportedInsecure = 1
policyBit IterationsInsecure = 2
policyBit NoSha1 = 4

||| No flag shares a bit with another (checked by evaluation: each pair's AND is 0).
export
policyBitsDisjoint : ( prim__and_Bits32 1 2 = 0
                     , prim__and_Bits32 1 4 = 0
                     , prim__and_Bits32 2 4 = 0 )
policyBitsDisjoint = (Refl, Refl, Refl)

||| The policy word for a list of flags (duplicates are harmless).
public export
policyWord : List PolicyFlag -> Bits32
policyWord = foldr (\f, acc => prim__or_Bits32 (policyBit f) acc) 0
