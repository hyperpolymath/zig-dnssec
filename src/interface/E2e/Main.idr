-- SPDX-License-Identifier: MPL-2.0
-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
||| End-to-end test of the seam: Idris2 -> C ABI -> Zig validator, over the
||| recorded cross-check responses (tests/testdata/). Exits non-zero on any
||| failure.
|||
||| Usage: abi-e2e <crosscheck.traces> <crosscheck-root.anchor>

module E2e.Main

import Abi.Types
import Abi.Foreign
import Data.List
import Data.Maybe
import Data.String
import System
import System.File

%default total

||| 2026-10-14T00:00:00Z: inside the fixtures' signing window.
now : Int64
now = 1791936000

||| The trace lines of one recorded scenario.
scenario : String -> String -> String -> String
scenario traces qname qtype =
  let header = "@query " ++ qname ++ " " ++ qtype ++ " "
      rest = drop 1 (dropWhile (not . isPrefixOf header) (lines traces))
  in unlines (takeWhile (not . isPrefixOf "@query ") rest)

data Check = Pass String | Fail String

check : String -> Bool -> Check
check name True = Pass name
check name False = Fail name

isReason : Reason -> Maybe Reason -> Bool
isReason r (Just r') = reasonCode r == reasonCode r'
isReason _ Nothing = False

||| A usable outcome's answer, if any. Bogus and Indeterminate have none to give.
answerText : Outcome -> Maybe String
answerText o = case usable o.security of
  Yes ok => Just (answerOf o ok)
  No _ => Nothing

expectSecure : String -> Either CallError Outcome -> Check
expectSecure name (Right o@(MkOutcome Secure Nothing "" _ _ _ _ _ _)) =
  check name (maybe False (isPrefixOf "www.rsasha256.test.") (answerText o))
expectSecure name _ = Fail name

expectInsecure : String -> Reason -> String -> Either CallError Outcome -> Check
expectInsecure name r zone (Right o@(MkOutcome Insecure why loc _ _ _ _ _ _)) =
  check name (isReason r why && loc == zone && isJust (answerText o))
expectInsecure name _ _ _ = Fail name

expectBogus : String -> Reason -> Either CallError Outcome -> Check
expectBogus name r (Right (MkOutcome Bogus why _ _ _ _ _ _ ())) = check name (isReason r why)
expectBogus name _ _ = Fail name

expectBogusAny : String -> Either CallError Outcome -> Check
expectBogusAny name (Right (MkOutcome Bogus _ _ _ _ _ _ _ ())) = Pass name
expectBogusAny name _ = Fail name

expectRefused : String -> Status -> Either CallError Outcome -> Check
expectRefused name s (Left (Refused s')) = check name (statusCode s == statusCode s')
expectRefused name _ _ = Fail name

isFail : Check -> Bool
isFail (Fail _) = True
isFail (Pass _) = False

||| Validates one recorded scenario against the fixture anchor.
runQ : (traces, anchor, qname, qtype : String) -> Bits16 -> List PolicyFlag -> IO (Either CallError Outcome)
runQ traces anchor q t ty pol = validateTrace (scenario traces q t) (Just anchor) q ty now pol

report : List Check -> IO Bool
report cs = do
  traverse_ (\c => case c of
                     Pass n => putStrLn ("PASS  " ++ n)
                     Fail n => putStrLn ("FAIL  " ++ n)) cs
  let failed = length (filter isFail cs)
  putStrLn (show (length cs) ++ " checks, " ++ show failed ++ " failed")
  pure (failed == 0)

covering
main : IO ()
main = do
  [_, tracesPath, anchorPath] <- getArgs
    | _ => do putStrLn "usage: abi-e2e <crosscheck.traces> <crosscheck-root.anchor>"; exitWith (ExitFailure 2)
  Right traces <- readFile tracesPath
    | Left e => do putStrLn ("cannot read " ++ tracesPath ++ ": " ++ show e); exitWith (ExitFailure 2)
  Right anchor <- readFile anchorPath
    | Left e => do putStrLn ("cannot read " ++ anchorPath ++ ": " ++ show e); exitWith (ExitFailure 2)
  let run = runQ traces anchor
  linked <- linkedAbiVersion
  secure <- run "www.rsasha256.test." "A" 1 []
  insecure <- run "www.insecure.test." "A" 1 []
  expired <- run "www.expired.test." "A" 1 []
  ed448 <- run "www.ed448.test." "A" 1 []
  ed448Policy <- run "www.ed448.test." "A" 1 [UnsupportedInsecure]
  badName <- run "a..b" "A" 1 []
  meta <- run "www.rsasha256.test." "A" 255 []
  ianaRoot <- validateTrace (scenario traces "www.rsasha256.test." "A") Nothing "www.rsasha256.test." 1 now []
  ok <- report
    [ check "linked library speaks ABI version 1" (linked == abiVersion)
    , expectSecure "secure answer with its records" secure
    , expectInsecure "insecure delegation, zone and answer" InsecureDelegation "insecure.test." insecure
    , expectBogus "expired signatures are bogus, with no answer" SignatureExpired expired
    , expectBogus "Ed448 is bogus by default" UnsupportedAlgorithm ed448
    , expectInsecure "Ed448 is insecure under the RFC policy" UnsupportedAlgorithmPolicy "ed448.test." ed448Policy
    , expectRefused "a malformed name is refused" BadName badName
    , expectRefused "a meta-type is refused" InvalidArgument meta
    , expectBogusAny "the IANA root does not sign the fixtures" ianaRoot
    ]
  if ok then exitSuccess else exitWith (ExitFailure 1)
