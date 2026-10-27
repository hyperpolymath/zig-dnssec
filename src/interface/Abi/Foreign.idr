-- SPDX-License-Identifier: MPL-2.0
-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
||| Idris2 bindings to the zig-dnssec C ABI (libzig_dnssec, built by
||| `zig build ffi`), and a safe wrapper whose result type keeps the seam's
||| rule: an answer is only ever returned with a Secure or Insecure verdict.
|||
||| The wrapper does not trust the library to keep that rule. It decodes the
||| verdict first and reads answer text only when the decoded security is
||| usable, so even a library that wrote text for a Bogus verdict could not
||| hand it to an Idris caller.
|||
||| What is trusted here, and not proved: that the foreign signatures below
||| match the header (checked by `zig build test`, which parses this file), and
||| the Chez/RefC FFI marshalling itself. Raw struct fields are read
||| little-endian, as Data.Buffer does; big-endian targets are not supported.

module Abi.Foreign

import Abi.Types
import Abi.Layout
import Data.Buffer
import Data.Fin
import Data.Vect

%default total

--------------------------------------------------------------------------------
-- Raw bindings (types follow zig_dnssec.h)
--------------------------------------------------------------------------------

%foreign "C:zig_dnssec_abi_version,libzig_dnssec"
prim__abiVersion : PrimIO Bits32

-- trace, anchors, qname, qtype, now, policy, out, text, text_cap
%foreign "C:zig_dnssec_validate_trace,libzig_dnssec"
prim__validateTrace : String -> String -> String -> Bits16 -> Int64 -> Bits32 -> Buffer -> Buffer -> Bits64 -> PrimIO Int

-- The same function with anchors = NULL (the built-in IANA root anchors).
%foreign "C:zig_dnssec_validate_trace,libzig_dnssec"
prim__validateTraceRoot : String -> AnyPtr -> String -> Bits16 -> Int64 -> Bits32 -> Buffer -> Buffer -> Bits64 -> PrimIO Int

||| The ABI version this binding was written for.
public export
abiVersion : Bits32
abiVersion = 1

||| The ABI version of the library actually loaded.
export
linkedAbiVersion : HasIO io => io Bits32
linkedAbiVersion = primIO prim__abiVersion

--------------------------------------------------------------------------------
-- Results
--------------------------------------------------------------------------------

||| A decoded verdict. The type of `answer` depends on `security`: text for
||| Secure and Insecure, `()` for Bogus and Indeterminate (Abi.Types.AnswerFor).
public export
record Outcome where
  constructor MkOutcome
  security : Security
  reason : Maybe Reason
  ||| Zone where insecurity was established, or name where validation failed.
  location : String
  rcode : Bits16
  rtype : Bits16
  ttl : Bits32
  fetches : Bits32
  verifications : Bits32
  answer : AnswerFor security

||| The answer of a usable outcome. There is no way to call this for a Bogus or
||| Indeterminate outcome: no `Usable` value exists for them.
export
answerOf : (o : Outcome) -> Usable o.security -> String
answerOf (MkOutcome Secure _ _ _ _ _ _ _ a) UsableSecure = a
answerOf (MkOutcome Insecure _ _ _ _ _ _ _ a) UsableInsecure = a

public export
data CallError
  = ||| The library refused the call (status other than OK).
    Refused Status
  | ||| The library broke the header's contract (an unknown code, or OK with no verdict).
    BrokenContract String
  | ||| Could not allocate the buffers.
    NoMemory

public export
Show CallError where
  show (Refused s) = "refused: " ++ show s
  show (BrokenContract m) = "broken contract: " ++ m
  show NoMemory = "out of memory"

--------------------------------------------------------------------------------
-- Reading the raw verdict
--------------------------------------------------------------------------------

verdictSize : Int
verdictSize = cast verdictLayout.totalSize

off : (i : Fin 10) -> (n : String) -> {auto 0 named : (index i Abi.Layout.verdictFields).name = n} -> Int
off i n = cast (offsetNamed i n)

||| Length of the NUL-terminated string at `off`, at most `limit` bytes.
cStringLength : HasIO io => Buffer -> (off : Int) -> (limit : Nat) -> io Int
cStringLength buf off limit = go 0 limit
  where
    go : Int -> Nat -> io Int
    go n Z = pure n
    go n (S k) = do
      b <- getBits8 buf (off + n)
      if b == 0 then pure n else go (n + 1) k

||| Decodes the verdict struct. `readText` is run only for usable verdicts.
decodeVerdict : HasIO io => Buffer -> (readText : Bits32 -> io String) -> io (Either CallError Outcome)
decodeVerdict v readText = do
  sec <- getBits8 v (off 0 "security")
  rsn <- getBits8 v (off 1 "reason")
  rc <- getBits16 v (off 3 "rcode")
  rt <- getBits16 v (off 4 "rtype")
  tl <- getBits32 v (off 5 "ttl")
  fe <- getBits32 v (off 6 "fetches")
  ve <- getBits32 v (off 7 "verifications")
  tlen <- getBits32 v (off 8 "text_len")
  wlen <- cStringLength v (off 9 "where") (minus whereMax 1)
  loc <- getString v (off 9 "where") wlen
  let reason = if rsn == 0 then Right Nothing else maybe (Left rsn) (Right . Just) (reasonFromCode rsn)
  case (securityFromCode sec, reason) of
    (Nothing, _) => pure (Left (BrokenContract ("security code " ++ show sec ++ " with status OK")))
    (_, Left r) => pure (Left (BrokenContract ("unknown reason code " ++ show r)))
    (Just Secure, Right why) => do
      t <- readText tlen
      pure (Right (MkOutcome Secure why loc rc rt tl fe ve t))
    (Just Insecure, Right why) => do
      t <- readText tlen
      pure (Right (MkOutcome Insecure why loc rc rt tl fe ve t))
    (Just Bogus, Right why) => pure (Right (MkOutcome Bogus why loc rc rt tl fe ve ()))
    (Just Indeterminate, Right why) => pure (Right (MkOutcome Indeterminate why loc rc rt tl fe ve ()))

--------------------------------------------------------------------------------
-- Safe wrapper
--------------------------------------------------------------------------------

||| Validates `qname`/`qtype` against a recorded trace (see
||| zig_dnssec_validate_trace). `anchors` Nothing selects the built-in IANA root
||| anchors. `now` is seconds since the Unix epoch. The answer buffer starts at
||| 64 KiB and is retried once at the size the library reports.
export
validateTrace : HasIO io =>
                (trace : String) -> (anchors : Maybe String) -> (qname : String) ->
                (qtype : Bits16) -> (now : Int64) -> (policy : List PolicyFlag) ->
                io (Either CallError Outcome)
validateTrace trace anchors qname qtype now policy = attempt 65536 (S Z)
  where
    call : Buffer -> Buffer -> Int -> io Int
    call out text cap = case anchors of
      Just a => primIO (prim__validateTrace trace a qname qtype now (policyWord policy) out text (cast cap))
      Nothing => primIO (prim__validateTraceRoot trace prim__getNullAnyPtr qname qtype now (policyWord policy) out text (cast cap))

    attempt : Int -> Nat -> io (Either CallError Outcome)
    attempt cap retries = do
      Just out <- newBuffer verdictSize | Nothing => pure (Left NoMemory)
      Just text <- newBuffer cap | Nothing => pure (Left NoMemory)
      st <- call out text cap
      case statusFromCode st of
        Nothing => pure (Left (BrokenContract ("status code " ++ show st)))
        Just Ok => decodeVerdict out (\n => getString text 0 (cast n))
        Just BufferTooSmall => case retries of
          S k => do
            need <- getBits32 out (off 8 "text_len")
            attempt (cast need + 1) k
          Z => pure (Left (Refused BufferTooSmall))
        Just s => pure (Left (Refused s))
