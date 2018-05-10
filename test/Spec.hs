{-# LANGUAGE OverloadedStrings #-}

import           Crypto.Hash.Keccak
import qualified Data.ByteString as BS
import           Test.Framework                       (defaultMain, Test, testGroup)
import           Test.Framework.Providers.HUnit       (testCase)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.HUnit                           (Assertion, assertEqual)
import           Test.QuickCheck                      (Property, (==>))

main :: IO ()
main = defaultMain tests


tests :: [Test]
tests = [ testGroup "padding"
            [ testCase "proper padding for keccak256" keccakPaddingTest
            ]
        , testGroup "keccak256"
            [ testCase "hashing empty bytestring" keccak256EmptyTest
            , testCase "hashing string 'testing'" keccak256AsciiStringTest ]
        ]


keccakPaddingTest :: Assertion
keccakPaddingTest = assertEqual "Pads ascii string properly" (paddingKeccak "testing") ""


keccak256EmptyTest :: Assertion
keccak256EmptyTest = assertEqual "Hashes empty string" (keccak256 BS.empty) ("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" :: BS.ByteString)


keccak256AsciiStringTest :: Assertion
keccak256AsciiStringTest = assertEqual "Hashes ascii string" (keccak256 "testing") ("5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02" :: BS.ByteString)
