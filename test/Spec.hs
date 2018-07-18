{-# LANGUAGE OverloadedStrings #-}

import           Crypto.Hash.Keccak
import qualified Data.ByteString                      as BS
import qualified Data.ByteString.Base16               as BS16
import           Data.Either
import           Test.Cryptonite
import           Test.Framework                       (defaultMain, Test, testGroup)
import           Test.Framework.Providers.HUnit       (testCase)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.HUnit                           (Assertion, assertEqual, assertFailure)
import           Test.Parse.KAT


main :: IO ()
main = defaultMain tests


tests :: [Test]
tests = [ testGroup "Keccak KAT"
            [ testCase "Keccak-224 ShortMsg KAT" shortMsgKAT_224
            , testCase "Keccak-224 LongMsg  KAT" longMsgKAT_224
            , testCase "Keccak-256 ShortMsg KAT" shortMsgKAT_256
            , testCase "Keccak-256 LongMsg  KAT" longMsgKAT_256
            , testCase "Keccak-256 ShortMsg KAT" shortMsgKAT_384
            , testCase "Keccak-384 LongMsg  KAT" longMsgKAT_384
            , testCase "Keccak-512 ShortMsg KAT" shortMsgKAT_512
            , testCase "Keccak-512 LongMsg  KAT" longMsgKAT_512
            ]
        , testGroup "SHA3 KAT"
            [ testCase "SHA3-224 ShortMsg KAT" shortMsgKAT_SHA3_224
            , testCase "SHA3-244 LongMsg  KAT" longMsgKAT_SHA3_224
            , testCase "SHA3-256 ShortMsg KAT" shortMsgKAT_SHA3_256
            , testCase "SHA3-256 LongMsg  KAT" longMsgKAT_SHA3_256
            , testCase "SHA3-384 ShortMsg KAT" shortMsgKAT_SHA3_384
            , testCase "SHA3-384 LongMsg  KAT" longMsgKAT_SHA3_384
            , testCase "SHA3-512 ShortMsg KAT" shortMsgKAT_SHA3_512
            , testCase "SHA3-512 LongMsg  KAT" longMsgKAT_SHA3_512
            ]
        , testGroup "SHAKE"
            [ testCase "SHAKE-128 ShortMsg KAT" shortMsgKAT_SHAKE_128
            , testCase "SHAKE-128 LongMsg  KAT" longMsgKAT_SHAKE_128
            , testCase "SHAKE-256 ShortMsg KAT" shortMsgKAT_SHAKE_256
            , testCase "SHAKE-256 LongMsg  KAT" longMsgKAT_SHAKE_256
            -- TODO add support for variable-length output tests
            ]
        ]


knownAnswerTestAssertion :: FilePath -> (BS.ByteString -> BS.ByteString) -> Assertion
knownAnswerTestAssertion testFile hashFunction = do
    katsE <- parseFromFile parseTestFile testFile
    kats <- either (assertFailure . show)
                   (pure . filter (\kat -> byteLength kat `mod` 8 == 0)) katsE
    mapM_ runKat $ zip [0..] kats
    where runKat (index, KAT l m d) = assertEqual (show index ++ ": Bad digest.")
                                                  (hashFunction $ BS.take l m) d


knownAnswerTestShakeAssertion :: FilePath -> (Int -> BS.ByteString -> BS.ByteString) -> Assertion
knownAnswerTestShakeAssertion testFile hashFunction = do
    katsE <- parseFromFile parseShakeTestFile testFile
    (len, kats) <- either (assertFailure . show)
                          (\(ShakeTestFile len kats) -> pure (len, filter (\kat -> byteLength kat `mod` 8 == 0) kats)) katsE
    mapM_ (runKat len) $ zip [0..] kats
    where runKat len (index, KAT l m d) = assertEqual (show index ++ ": Bad digest.")
                                                      (hashFunction len $ BS.take l m) d


shortMsgKAT_224 :: Assertion
shortMsgKAT_224 = knownAnswerTestAssertion "test/KAT_MCT/ShortMsgKAT_224.txt" keccak224

longMsgKAT_224 :: Assertion
longMsgKAT_224 = knownAnswerTestAssertion "test/KAT_MCT/LongMsgKAT_224.txt" keccak224

shortMsgKAT_256 :: Assertion
shortMsgKAT_256 = knownAnswerTestAssertion "test/KAT_MCT/ShortMsgKAT_256.txt" keccak256

longMsgKAT_256 :: Assertion
longMsgKAT_256 = knownAnswerTestAssertion "test/KAT_MCT/LongMsgKAT_256.txt" keccak256

shortMsgKAT_384 :: Assertion
shortMsgKAT_384 = knownAnswerTestAssertion "test/KAT_MCT/ShortMsgKAT_384.txt" keccak384

longMsgKAT_384 :: Assertion
longMsgKAT_384 = knownAnswerTestAssertion "test/KAT_MCT/LongMsgKAT_384.txt" keccak384

shortMsgKAT_512 :: Assertion
shortMsgKAT_512 = knownAnswerTestAssertion "test/KAT_MCT/ShortMsgKAT_512.txt" keccak512

longMsgKAT_512 :: Assertion
longMsgKAT_512 = knownAnswerTestAssertion "test/KAT_MCT/LongMsgKAT_512.txt" keccak512

shortMsgKAT_SHA3_224 :: Assertion
shortMsgKAT_SHA3_224 = knownAnswerTestAssertion "test/KAT_MCT/SHA3_224ShortMsg.rsp" sha3_224

longMsgKAT_SHA3_224 :: Assertion
longMsgKAT_SHA3_224 = knownAnswerTestAssertion "test/KAT_MCT/SHA3_224LongMsg.rsp" sha3_224

shortMsgKAT_SHA3_256 :: Assertion
shortMsgKAT_SHA3_256 = knownAnswerTestAssertion "test/KAT_MCT/SHA3_256ShortMsg.rsp" sha3_256

longMsgKAT_SHA3_256 :: Assertion
longMsgKAT_SHA3_256 = knownAnswerTestAssertion "test/KAT_MCT/SHA3_256LongMsg.rsp" sha3_256

shortMsgKAT_SHA3_384 :: Assertion
shortMsgKAT_SHA3_384 = knownAnswerTestAssertion "test/KAT_MCT/SHA3_384ShortMsg.rsp" sha3_384

longMsgKAT_SHA3_384 :: Assertion
longMsgKAT_SHA3_384 = knownAnswerTestAssertion "test/KAT_MCT/SHA3_384LongMsg.rsp" sha3_384

shortMsgKAT_SHA3_512 :: Assertion
shortMsgKAT_SHA3_512 = knownAnswerTestAssertion "test/KAT_MCT/SHA3_512ShortMsg.rsp" sha3_512

longMsgKAT_SHA3_512 :: Assertion
longMsgKAT_SHA3_512 = knownAnswerTestAssertion "test/KAT_MCT/SHA3_512LongMsg.rsp" sha3_512

shortMsgKAT_SHAKE_128 :: Assertion
shortMsgKAT_SHAKE_128 = knownAnswerTestShakeAssertion "test/KAT_MCT/SHAKE128ShortMsg.rsp" shake128

longMsgKAT_SHAKE_128 :: Assertion
longMsgKAT_SHAKE_128 = knownAnswerTestShakeAssertion "test/KAT_MCT/SHAKE128LongMsg.rsp" shake128

shortMsgKAT_SHAKE_256 :: Assertion
shortMsgKAT_SHAKE_256 = knownAnswerTestShakeAssertion "test/KAT_MCT/SHAKE256ShortMsg.rsp" shake256

longMsgKAT_SHAKE_256 :: Assertion
longMsgKAT_SHAKE_256 = knownAnswerTestShakeAssertion "test/KAT_MCT/SHAKE256LongMsg.rsp" shake256
