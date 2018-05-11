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
            [ testCase "proper padding for keccak256" keccakEmptyPaddingTest
            , testCase "proper padding for keccak256" keccakAsciiPaddingTest
            ]
        , testGroup "keccak256"
            [ testCase "hashing empty bytestring" keccak256EmptyTest
            , testCase "hashing string 'testing'" keccak256AsciiStringTest ]
        ]


keccakEmptyPaddingTest :: Assertion
keccakEmptyPaddingTest = assertEqual "Pads empty string properly" zeroPadding (paddingKeccak "")
    where zeroPadding = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128]

keccakAsciiPaddingTest :: Assertion
keccakAsciiPaddingTest = assertEqual "Pads ascii string properly" asciiPadding (paddingKeccak "testing")
    where asciiPadding = [116, 101, 115, 116, 105, 110, 103, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128]


keccak256EmptyTest :: Assertion
keccak256EmptyTest = assertEqual "Hashes empty string" ("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" :: BS.ByteString) (keccak256 BS.empty)


keccak256AsciiStringTest :: Assertion
keccak256AsciiStringTest = assertEqual "Hashes ascii string" ("5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02" :: BS.ByteString) (keccak256 "testing")
