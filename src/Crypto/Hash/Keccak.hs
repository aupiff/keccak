module Crypto.Hash.Keccak
    ( keccak256
    , paddingKeccak
    ) where

import qualified Data.ByteString as BS

roundConstants = [ 0x0000000000000001, 0x0000000000008082, 0x800000000000808A
                 , 0x8000000080008000, 0x000000000000808B, 0x0000000080000001
                 , 0x8000000080008081, 0x8000000000008009, 0x000000000000008A
                 , 0x0000000000000088, 0x0000000080008009, 0x000000008000000A
                 , 0x000000008000808B, 0x800000000000008B, 0x8000000000008089
                 , 0x8000000000008003, 0x8000000000008002, 0x8000000000000080
                 , 0x000000000000800A, 0x800000008000000A, 0x8000000080008081
                 , 0x8000000000008080, 0x0000000080000001, 0x8000000080008008 ]

paddingKeccak :: BS.ByteString -> BS.ByteString
paddingKeccak = multiratePadding 0x1


paddingSha3 :: BS.ByteString -> BS.ByteString
paddingSha3 = multiratePadding 0x6

multiratePadding :: Word -> BS.ByteString -> BS.ByteString
multiratePadding pad input = if padlen == 1
    then BS.pack [0x81]
    else BS.pack $ 0x01 : replicate (padlen - 2) 0x00 ++ [0x80]
    where bitRateBytes = 32
          -- TODO: modulo bitRateBytes?
          usedBytes = BS.length input
          padlen = bitRateBytes - usedBytes

keccak256 :: BS.ByteString -> BS.ByteString
keccak256 input = BS.append input $ paddingKeccak input
