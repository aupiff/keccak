{-# LANGUAGE BangPatterns #-}

module Crypto.Hash.Keccak
    ( -- * Standard keccak hash functions
      keccak224
    , keccak256
    , keccak384
    , keccak512
      -- * Standard SHA3 hash functions
    , sha3_512
    , sha3_384
    , sha3_256
    , sha3_224
      -- * SHAKE extendable-output functions
    , shake128
    , shake256
      -- * Building blocks of a Keccak hash function
    , keccakHash
    , sha3Hash
    , paddingKeccak
    , paddingSha3
    , absorb
    , squeeze
    ) where

import           Data.Bits
import qualified Data.ByteString             as BS
import qualified Data.ByteString.Builder     as BS
import qualified Data.ByteString.Lazy        as LBS
import           Data.Foldable
import           Data.Monoid
import           Data.Vector.Unboxed         ((!))
import qualified Data.Vector.Unboxed         as V
import qualified Data.Vector.Unboxed.Mutable as MV
import           Data.Word
import           Prelude                     hiding (pi)

rounds :: Int
rounds = 24

numLanes :: Int
numLanes = 25

laneWidth :: Int
laneWidth = 64

emptyState :: V.Vector Word64
emptyState = V.replicate numLanes 0

----------------------------------------------------
-- Constants used in KeccakF[1600] permutation
----------------------------------------------------

roundConstants :: V.Vector Word64
roundConstants = V.fromList [ 0x0000000000000001, 0x0000000000008082, 0x800000000000808A
                            , 0x8000000080008000, 0x000000000000808B, 0x0000000080000001
                            , 0x8000000080008081, 0x8000000000008009, 0x000000000000008A
                            , 0x0000000000000088, 0x0000000080008009, 0x000000008000000A
                            , 0x000000008000808B, 0x800000000000008B, 0x8000000000008089
                            , 0x8000000000008003, 0x8000000000008002, 0x8000000000000080
                            , 0x000000000000800A, 0x800000008000000A, 0x8000000080008081
                            , 0x8000000000008080, 0x0000000080000001, 0x8000000080008008 ]

rotationConstants :: V.Vector Int
rotationConstants = V.fromList [  0, 36,  3, 41, 18
                               ,  1, 44, 10, 45,  2
                               , 62,  6, 43, 15, 61
                               , 28, 55, 25, 21, 56
                               , 27, 20, 39,  8, 14 ]

-- TODO explain how these are generated
piConstants :: V.Vector Int
piConstants = V.fromList [ 0, 15, 5, 20, 10
                         , 6, 21, 11, 1, 16
                         , 12, 2, 17, 7, 22
                         , 18, 8, 23, 13, 3
                         , 24, 14, 4, 19, 9 ]

----------------------------------------------------
-- Keccak and SHA3 hash functions
----------------------------------------------------

hashFunction :: (Int -> BS.ByteString -> V.Vector Word8) -> Int -> BS.ByteString -> BS.ByteString
hashFunction paddingFunction rate = squeeze rate outputBytes . absorb rate
                                                             . paddingFunction (div rate 8)
    where outputBytes = div (1600 - rate) 16

-- | Given a bitrate @r@, returns a standard Keccak hash with state width @w@ = 1600 and
-- capacity = 1600 - @r@
keccakHash :: Int -> BS.ByteString -> BS.ByteString
keccakHash = hashFunction paddingKeccak

-- | Given a bitrate @r@, returns a standard SHA3 hash with state width @w@ = 1600 and
-- capacity = 1600 - @r@
sha3Hash :: Int -> BS.ByteString -> BS.ByteString
sha3Hash = hashFunction paddingSha3


-- | Keccak (512 bits) cryptographic hash algorithm
keccak512 :: BS.ByteString -> BS.ByteString
keccak512 = keccakHash 576


-- | Keccak (384 bits) cryptographic hash algorithm
keccak384 :: BS.ByteString -> BS.ByteString
keccak384 =  keccakHash 832


-- | Keccak (256 bits) cryptographic hash algorithm
keccak256 :: BS.ByteString -> BS.ByteString
keccak256 = keccakHash 1088


-- | Keccak (224 bits) cryptographic hash algorithm
keccak224 :: BS.ByteString -> BS.ByteString
keccak224 = keccakHash 1152


-- | SHA3 (512 bits) cryptographic hash algorithm
sha3_512 :: BS.ByteString -> BS.ByteString
sha3_512 = sha3Hash 576


-- | SHA3 (384 bits) cryptographic hash algorithm
sha3_384 :: BS.ByteString -> BS.ByteString
sha3_384 = sha3Hash 832


-- | SHA3 (256 bits) cryptographic hash algorithm
sha3_256 :: BS.ByteString -> BS.ByteString
sha3_256 = sha3Hash 1088


-- | SHA3 (224 bits) cryptographic hash algorithm
sha3_224 :: BS.ByteString -> BS.ByteString
sha3_224 = sha3Hash 1152

----------------------------------------------------
-- SHAKE Extendable-Output Functions
----------------------------------------------------

shakeFunction :: (Int -> BS.ByteString -> V.Vector Word8) -> Int
              -> Int -> BS.ByteString -> BS.ByteString
shakeFunction paddingFunction rate outputBytes =
        squeeze rate outputBytes . absorb rate
                                 . paddingFunction (div rate 8)


-- | SHAKE128 (128 bit security level) cryptographic extendable-output function
shake128 :: Int -> BS.ByteString -> BS.ByteString
shake128 outputBits = shakeFunction paddingShake 1344 (div outputBits 8)


-- | SHAKE256 (256 bit security level) cryptographic extendable-output function
shake256 :: Int -> BS.ByteString -> BS.ByteString
shake256 outputBits = shakeFunction paddingShake 1088 (div outputBits 8)


----------------------------------------------------
-- Padding functions
----------------------------------------------------

-- | Multi-rate padding appends at least 2 bits and at most the number of bits
-- in a block plus one.
multiratePadding :: Int -> Word8 -> BS.ByteString -> V.Vector Word8
multiratePadding bitrateBytes padByte input = V.generate totalLength process
    where msglen = BS.length input
          padlen = bitrateBytes - mod (BS.length input) bitrateBytes
          totalLength = padlen + msglen
          process x
            | x < msglen                            = BS.index input x
            | x == (totalLength - 1) && padlen == 1 = 0x80 .|. padByte
            | x == (totalLength - 1)                = 0x80
            | x == msglen                           = padByte
            | otherwise                             = 0x00

-- | Appends a single bit 1 followed by the minimum number of bits
-- 0 followed by a single bit 1 such that the length of the result is
-- a multiple of the bitrate.
paddingKeccak :: Int -> BS.ByteString -> V.Vector Word8
paddingKeccak bitrateBytes = multiratePadding bitrateBytes 0x01


-- | Appends to a message M padding of the form (M || 0x06 || 0x00... || 0x80)
-- such that the length of the result is a multiple of the bitrate.
paddingSha3 :: Int -> BS.ByteString -> V.Vector Word8
paddingSha3 bitrateBytes = multiratePadding bitrateBytes 0x06


paddingShake :: Int -> BS.ByteString -> V.Vector Word8
paddingShake bitrateBytes = multiratePadding bitrateBytes 0x1F

----------------------------------------------------
-- Sponge function primitives
----------------------------------------------------

toBlocks :: V.Vector Word8 -> V.Vector Word64
toBlocks = V.unfoldr toLane
    where toLane :: V.Vector Word8 -> Maybe (Word64, V.Vector Word8)
          toLane input
            | V.null input = Nothing
            | otherwise    = let (h, t) = V.splitAt 8 input
                             in Just (V.ifoldl' createWord64 0 h, t)
          createWord64 acc offset octet = acc `xor` shiftL (fromIntegral octet) (offset * 8)


-- | Takes as input the bitrate @rate@ and a string P with |P| a multiple of
-- @rate@. Returns the value of the state obtained after absorbing P.
absorb :: Int -> V.Vector Word8 -> V.Vector Word64
absorb rate = absorbBlock rate emptyState . toBlocks


absorbBlock :: Int -> V.Vector Word64 -> V.Vector Word64 -> V.Vector Word64
absorbBlock !rate !state !input
    | V.null input = state
    | otherwise    = absorbBlock rate (keccakF state') (V.drop (div rate 64) input)
    -- TODO this can be optimized with some sort of in-place manipulation
    where state' = V.imap (\z el -> if div z 5 + 5 * mod z 5 < threshold
                                    then el `xor` (input ! (div z 5 + 5 * mod z 5))
                                    else el) state
          threshold = div rate laneWidth


-- | Iteratively returns the outer part of the state as output blocks, interleaved
-- with applications of the function @keccakF@. The number of iterations is
-- determined by the requested number of bits @l@.
squeeze :: Int -> Int -> V.Vector Word64 -> BS.ByteString
squeeze !rate !l !state = BS.take l . LBS.toStrict . BS.toLazyByteString
                                    . V.foldl' (\acc n -> acc <> BS.word64LE n) mempty
                                    $ stateToBytes state
    where lanesToExtract = ceiling $ fromIntegral l / fromIntegral (div laneWidth 8)
          stateToBytes :: V.Vector Word64 -> V.Vector Word64
          stateToBytes s = V.unfoldrN lanesToExtract extract (0, s)
          threshold = div rate laneWidth
          extract (x, s)
            | x < threshold = Just (s ! (div x 5 + mod x 5 * 5), (succ x, s))
            | otherwise     = extract (0, keccakF s)

----------------------------------------------------
-- KeccakF permutation & constituent primatives
----------------------------------------------------

keccakF :: V.Vector Word64 -> V.Vector Word64
keccakF !state = snd $ foldl1 (.) (replicate rounds f) (0, state)
    where f (!r, !s) = (succ r, iota r . chi . pi . rho $ theta s)


theta :: V.Vector Word64 -> V.Vector Word64
theta !state = V.concatMap (\(i, e) -> V.map (xor e) (V.slice (i * 5) 5 state)) $ V.indexed d
    where c = V.generate 5 (\i -> V.foldl1' xor (V.slice (i * 5) 5 state))
          d = V.generate 5 (\i -> c ! ((i - 1) `mod` 5) `xor` rotateL (c ! ((i + 1) `mod` 5)) 1)
{-# INLINE theta #-}


rho :: V.Vector Word64 -> V.Vector Word64
rho !state = V.zipWith (flip rotateL) rotationConstants state
{-# INLINE rho #-}


pi :: V.Vector Word64 -> V.Vector Word64
pi !state = V.backpermute state piConstants
{-# INLINE pi #-}


-- The only non-linear component of keccakF
chi :: V.Vector Word64 -> V.Vector Word64
chi !b = V.imap subChi b
    where subChi z el = el `xor` (complement (b ! mod (z + 5) 25) .&. (b ! mod (z + 10) 25))
{-# INLINE chi #-}


iota :: Int -> V.Vector Word64 -> V.Vector Word64
iota !roundNumber !state = V.modify (\v -> MV.write v 0 $ xor (roundConstants ! roundNumber) (V.head state)) state
{-# INLINE iota #-}
