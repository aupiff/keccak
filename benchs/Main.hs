{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Crypto.Hash.Keccak
import           Test.Cryptonite
import qualified Data.ByteString    as BS

import Gauge

-- TODO short test & long test for multiple hashes
stringsToHash :: [BS.ByteString]
stringsToHash =  ["", "testing", "1234891237489127349817238497"]

main = defaultMain
    [ bench "keccak" $ nf (map keccak256) stringsToHash
    , bench "cryptonite-keccak" $ nf (map cryptoniteKeccak') stringsToHash
    ]
