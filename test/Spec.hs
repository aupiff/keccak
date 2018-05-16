{-# LANGUAGE OverloadedStrings #-}

import           Crypto.Hash.Keccak
import qualified Data.ByteString                      as BS
import qualified Data.ByteString.Base16               as BS16
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
            , testCase "hashing string 'testing'" keccak256AsciiTest
            ]
        ]


keccakEmptyPaddingTest :: Assertion
keccakEmptyPaddingTest = assertEqual "Pads empty string properly" zeroPadding (paddingKeccak "")
    where zeroPadding = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128]

keccakAsciiPaddingTest :: Assertion
keccakAsciiPaddingTest = assertEqual "Pads ascii string properly" asciiPadding (paddingKeccak "testing")
    where asciiPadding = [116, 101, 115, 116, 105, 110, 103, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128]


keccakEmptyAbsorbtionTest :: Assertion
keccakEmptyAbsorbtionTest = assertEqual "Absorbs empty input properly" endState (absorb . toBlocks 136 $ paddingKeccak "")
    where endState = [[4333579421379646149,14671339323370021561,4391692840257016808,16970298442240338249,16062291397582171322],[13836122230913597074,2243375101132795228,4309499098775122448,1971761234120675839,1601982631079003425],[4262519377828905189,9371364203318886753,13438072403645551266,450719451514497906,7734681229251997073],[8116759062988257915,9347994793612953298,18018124564071650747,18340686150147091359,13256946727218518206],[8406387447366859581,12814238161780307547,4323130096954625545,11254645818134300982,11816912122432958423]]


keccakAsciiAbsorbtionTest :: Assertion
keccakAsciiAbsorbtionTest = assertEqual "Absorbs ascii input properly" asciiState (absorb . toBlocks 136 $ paddingKeccak "testing")
    where asciiState = [[5741044927781148255,5536040307487716601,11084357000576311707,12707954408119767660,8319093435246931416],[253595265147670677,7606140838194786578,2366244087054482559,18181979956023419548,7691975034864958586],[10448875313496118154,17475093054141481980,11669704621260022411,9601734410265320743,13113298532289803684],[151888593866888543,4052828971212897447,7607297586066738160,15654769812205594072,16061863611318168517],[3465997019864229635,12358594370410885724,17971813471771339249,7394790340576097786,5735185612101350050]]


keccak256EmptyTest :: Assertion
keccak256EmptyTest = assertEqual "Hashes empty string" ("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" :: BS.ByteString) (BS16.encode $ keccak256 BS.empty)


keccak256AsciiTest :: Assertion
keccak256AsciiTest = assertEqual "Hashes ascii string" ("5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02" :: BS.ByteString) (BS16.encode $ keccak256 "testing")
