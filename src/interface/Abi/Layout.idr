-- SPDX-License-Identifier: MPL-2.0
-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
||| Memory layout of `zig_dnssec_verdict` (src/interface/ffi/include/zig_dnssec.h),
||| with proofs that every field is aligned, that the fields are in order and do
||| not overlap, and that the struct size is a multiple of its alignment.
|||
||| The offsets here are compared with the C compiler's (`@offsetOf` of the
||| translated header) by `zig build test`, so this model and the real struct
||| cannot drift silently. The model assumes natural alignment and 8-bit bytes,
||| as on the 64-bit targets the library is built for; it is tested on x86_64
||| Linux only.

module Abi.Layout

import Data.Fin
import Data.Nat
import Data.So
import Data.Vect

%default total

--------------------------------------------------------------------------------
-- Layout model
--------------------------------------------------------------------------------

||| n divides m
public export
data Divides : (n, m : Nat) -> Type where
  MkDivides : (k : Nat) -> (0 prf : m = k * n) -> Divides n m

||| A field: name, byte offset, size and alignment.
public export
record Field where
  constructor MkField
  name : String
  offset : Nat
  size : Nat
  alignment : Nat

||| Every field is aligned.
public export
data FieldsAligned : Vect k Field -> Type where
  NoFields : FieldsAligned []
  ConsField :
    (f : Field) ->
    (0 prf : Divides f.alignment f.offset) ->
    FieldsAligned rest ->
    FieldsAligned (f :: rest)

||| Fields start at or after `from`, appear in increasing order without
||| overlapping, and the last one ends at or before `end`.
public export
data InOrder : (from, end : Nat) -> Vect k Field -> Type where
  Fits : (0 prf : So (lte from end)) -> InOrder from end []
  Next :
    (f : Field) ->
    (0 prf : So (lte from f.offset)) ->
    InOrder (f.offset + f.size) end rest ->
    InOrder from end (f :: rest)

||| A C-compatible struct layout.
public export
record StructLayout where
  constructor MkStructLayout
  {0 k : Nat}
  fields : Vect k Field
  totalSize : Nat
  alignment : Nat

||| What makes a layout valid: aligned fields, no overlap, size a multiple of
||| the alignment.
public export
record CABICompliant (l : StructLayout) where
  constructor CABIOk
  0 aligned : FieldsAligned l.fields
  0 ordered : InOrder 0 l.totalSize l.fields
  0 padded : Divides l.alignment l.totalSize

--------------------------------------------------------------------------------
-- zig_dnssec_verdict
--------------------------------------------------------------------------------

||| ZIG_DNSSEC_WHERE_MAX
public export
whereMax : Nat
whereMax = 1024

public export
verdictFields : Vect 10 Field
verdictFields =
  [ MkField "security"      0  1 1
  , MkField "reason"        1  1 1
  , MkField "reserved"      2  2 2
  , MkField "rcode"         4  2 2
  , MkField "rtype"         6  2 2
  , MkField "ttl"           8  4 4
  , MkField "fetches"       12 4 4
  , MkField "verifications" 16 4 4
  , MkField "text_len"      20 4 4
  , MkField "where"         24 1024 1
  ]

public export
verdictLayout : StructLayout
verdictLayout = MkStructLayout verdictFields 1048 4

export
verdictLayoutValid : CABICompliant Abi.Layout.verdictLayout
verdictLayoutValid = CABIOk
  (ConsField _ (MkDivides 0 Refl)
    (ConsField _ (MkDivides 1 Refl)
      (ConsField _ (MkDivides 1 Refl)
        (ConsField _ (MkDivides 2 Refl)
          (ConsField _ (MkDivides 3 Refl)
            (ConsField _ (MkDivides 2 Refl)
              (ConsField _ (MkDivides 3 Refl)
                (ConsField _ (MkDivides 4 Refl)
                  (ConsField _ (MkDivides 5 Refl)
                    (ConsField _ (MkDivides 24 Refl)
                      NoFields))))))))))
  (Next _ Oh (Next _ Oh (Next _ Oh (Next _ Oh (Next _ Oh
    (Next _ Oh (Next _ Oh (Next _ Oh (Next _ Oh (Next _ Oh
      (Fits Oh)))))))))))
  (MkDivides 262 Refl)

||| The offset of verdict field `i`, which must be called `n`: a reader that
||| names the wrong field does not typecheck.
public export
offsetNamed : (i : Fin 10) -> (n : String) -> {auto 0 named : (index i Abi.Layout.verdictFields).name = n} -> Nat
offsetNamed i _ = (index i verdictFields).offset
