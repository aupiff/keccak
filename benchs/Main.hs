{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Crypto.Hash        (Digest, Keccak_256, hash)
import           Crypto.Hash.Keccak
import           Data.ByteArray     (convert)
import qualified Data.ByteString    as BS

import Gauge

stringsToHash :: [BS.ByteString]
stringsToHash =  ["", "testing", "1234891237489127349817238497"]

main = defaultMain
    [ bench "keccak" $ nf (map keccak256) stringsToHash
    , bench "cryptonite-keccak" $ nf (map cryptoniteKeccak') stringsToHash
    ]

cryptoniteKeccak' :: BS.ByteString -> BS.ByteString
cryptoniteKeccak' = convert . cryptoniteKeccak

cryptoniteKeccak :: BS.ByteString -> Digest Keccak_256
cryptoniteKeccak = hash
