module Test.Cryptonite where

import           Crypto.Hash        (Digest, Keccak_256, hash)
import           Data.ByteArray     (convert)
import qualified Data.ByteString    as BS

cryptoniteKeccak' :: BS.ByteString -> BS.ByteString
cryptoniteKeccak' = convert . cryptoniteKeccak

cryptoniteKeccak :: BS.ByteString -> Digest Keccak_256
cryptoniteKeccak = hash
