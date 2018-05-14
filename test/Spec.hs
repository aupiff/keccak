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
tests = [ testGroup "padding & blocking"
            [ testCase "proper padding of zero input for keccak256" keccakEmptyPaddingTest
            , testCase "proper padding of ascii input for keccak256" keccakAsciiPaddingTest
            ]
        , testGroup "absorbtion"
            [ testCase "proper absorbtion of zero input for keccak256" keccakEmptyAbsorbtionTest
            , testCase "proper absorbtion of ascii input for keccak256" keccakAsciiAbsorbtionTest
            ]
        , testGroup "squeezing" []
        , testGroup "keccak256"
            [ testCase "hashing empty bytestring" keccak256EmptyTest
            , testCase "hashing string 'testing'" keccak256AsciiTest ]
        ]


keccakEmptyPaddingTest :: Assertion
keccakEmptyPaddingTest = assertEqual "Pads empty string properly" zeroPadding (paddingKeccak "")
    where zeroPadding = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128]

keccakAsciiPaddingTest :: Assertion
keccakAsciiPaddingTest = assertEqual "Pads ascii string properly" asciiPadding (paddingKeccak "testing")
    where asciiPadding = [116, 101, 115, 116, 105, 110, 103, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128]


keccakEmptyAbsorbtionTest :: Assertion
keccakEmptyAbsorbtionTest = assertEqual "Absorbs empty input properly" emptyState (foldl absorb emptyState . toBlocks 136 $ paddingKeccak "")
    where emptyState = [ [ 0x3c23f7860146d2c5, 0xc003c7dcb27d7e92, 0x3b2782ca53b600e5, 0x70a4855d04d8fa7b, 0x74a97cd82c9abb3d ] , [ 0xcb9b1161ecb0a2b9, 0x1f2211c4c0f9ed5c, 0x820dc6175fa24161, 0x81babfbcab8046d2, 0xb1d551b7242b765b ] , [ 0x3cf26d5eba2553e8, 0x3bce6a98fe5b7210, 0xba7d9fa73545d2a2, 0xfa0d3cd3b03b15bb, 0x3bfed7eb12c7ce09 ] , [ 0xeb829c854e19a949, 0x1b5d1a6545a611ff, 0x064146f400e16b72, 0xfe8734e16471ab9f, 0x9c3088bdeebb0936 ] , [ 0xdee8b8eca7b2acba, 0x163b62b71dcf4521, 0x6b571b9910726d91, 0xb7fa22cf622318be, 0xa3fe1af7779fafd7 ] ]


keccakAsciiAbsorbtionTest :: Assertion
keccakAsciiAbsorbtionTest = assertEqual "Absorbs ascii input properly" asciiState (foldl absorb emptyState . toBlocks 136 $ paddingKeccak "")
    where asciiState = [ [ 0x4fac49f1c7f4165f, 0x0384f38ccfd91095, 0x9101dcbcb348d38a, 0x021b9ddf12de955f, 0x3019b1ed0991e703 ] , [ 0x4cd3f754160cb4f9, 0x698e70cb14313112, 0xf284008bb4ffc3fc, 0x383e8a79fc8e7ca7, 0xab828c19eb7bb25c ] , [ 0x99d38bf6eef7219b, 0x20d69675d4c03c7f, 0xa1f31e8637f0228b, 0x69928cd96e31cbf0, 0xf968b5224282a9f1 ] , [ 0xb05bb9345dd6926c, 0xfc535e70100c629c, 0x85403692ef825d27, 0xd940ea33a105e5d8, 0x669f92a2ae8735fa ] , [ 0x73735b67252d6dd8, 0x6abf628a564c7c7a, 0xb5fbcb89b2c8f5a4, 0xdee733dae7646bc5, 0x4f9778ed8a3b72a2 ] ]


keccak256EmptyTest :: Assertion
keccak256EmptyTest = assertEqual "Hashes empty string" ("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" :: BS.ByteString) (keccak256 BS.empty)


keccak256AsciiTest :: Assertion
keccak256AsciiTest = assertEqual "Hashes ascii string" ("5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02" :: BS.ByteString) (keccak256 "testing")
