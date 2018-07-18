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
      -- * Building blocks of a Keccak hash function
    , keccakHash
    , sha3Hash
    , paddingKeccak
    , paddingSha3
    , absorb
    , squeeze
    ) where

import           Data.Bits
import qualified Data.ByteString            as BS
import           Data.Vector.Unboxed        ((!), (//))
import qualified Data.Vector.Unboxed        as V
import           Data.Word

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

----------------------------------------------------
-- Keccak and SHA3 hash functions
----------------------------------------------------

hashFunction :: (Int -> BS.ByteString -> V.Vector Word8) -> Int -> BS.ByteString -> BS.ByteString
hashFunction paddingFunction rate = squeeze outputBytes . absorb rate
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
-- Padding functions
----------------------------------------------------

-- | Multi-rate padding appends at least 2 bits and at most the number of bits
-- in a block plus one.
multiratePadding :: Int -> Word8 -> BS.ByteString -> V.Vector Word8
multiratePadding bitrateBytes padByte input = V.fromList . (++) (BS.unpack input) $ if padlen == 1
    then [0x80 .|. padByte]
    else padByte : replicate (padlen - 2) 0x00 ++ [0x80]
    where padlen = bitrateBytes - mod (BS.length input) bitrateBytes


-- | Appends a single bit 1 followed by the minimum number of bits
-- 0 followed by a single bit 1 such that the length of the result is
-- a multiple of the bitrate.
paddingKeccak :: Int -> BS.ByteString -> V.Vector Word8
paddingKeccak bitrateBytes = multiratePadding bitrateBytes 0x01


-- | Appends to a message M padding of the form (M || 0x06 || 0x00... || 0x80)
-- such that the length of the result is a multiple of the bitrate.
paddingSha3 :: Int -> BS.ByteString -> V.Vector Word8
paddingSha3 bitrateBytes = multiratePadding bitrateBytes 0x06

----------------------------------------------------
-- Sponge function primitives
----------------------------------------------------

toBlocks :: V.Vector Word8 -> V.Vector Word64
toBlocks = V.unfoldr toLane
    where toLane :: V.Vector Word8 -> Maybe (Word64, V.Vector Word8)
          toLane input
            | V.null input = Nothing
            | otherwise    = let (head, tail) = V.splitAt 8 input
                             in Just (V.ifoldl' createWord64 0 head, tail)
          createWord64 acc offset octet = acc `xor` shiftL (fromIntegral octet) (offset * 8)


-- | Takes as input the bitrate @rate@ and a string P with |P| a multiple of
-- @rate@. Returns the value of the state obtained after absorbing P.
absorb :: Int -> V.Vector Word8 -> V.Vector Word64
absorb rate = absorbBlock rate emptyState . toBlocks


absorbBlock :: Int -> V.Vector Word64 -> V.Vector Word64 -> V.Vector Word64
absorbBlock rate state input
    | V.null input = state
    | otherwise    = absorbBlock rate (keccakF state') (V.drop (div rate 64) input)
    -- TODO this can be optimized with some sort of in-place manipulation
    where state' = V.map (\z -> if div z 5 + 5 * mod z 5 < div rate laneWidth
                                    then (state ! z) `xor` (input ! (div z 5 + 5 * mod z 5))
                                    else state ! z)
                         (V.enumFromN 0 numLanes)

-- | Iteratively returns the outer part of the state as output blocks, interleaved
-- with applications of the function @keccakF@. The number of iterations is
-- determined by the requested number of bits @l@.
-- TODO make this support SHAKE
squeeze :: Int -> V.Vector Word64 -> BS.ByteString
squeeze l = BS.pack . V.toList . V.take l . stateToBytes


-- TODO this can probably be an unfold
stateToBytes :: V.Vector Word64 -> V.Vector Word8
stateToBytes state = V.concatMap (\z -> laneToBytes $ state ! (div z 5 + mod z 5 * 5)) (V.enumFromN 0 numLanes)


laneToBytes :: Word64 -> V.Vector Word8
laneToBytes = V.unfoldrN 8 (\x -> Just (fromIntegral $ x .&. 0xFF, shiftR x 8))

----------------------------------------------------
-- KeccakF permutation & constituent primatives
----------------------------------------------------

keccakF :: V.Vector Word64 -> V.Vector Word64
keccakF state = V.foldl' (\s r -> iota r . chi . rhoPi $ theta s) state (V.enumFromN 0 rounds)
    where rounds = 24


theta :: V.Vector Word64 -> V.Vector Word64
theta state = V.map (\z -> xor (d ! div z 5) (state ! z)) $ V.enumFromN 0 numLanes
    where c = V.fromList [ state ! 0  `xor` state ! 1  `xor` state ! 2  `xor` state ! 3  `xor` state ! 4
                         , state ! 5  `xor` state ! 6  `xor` state ! 7  `xor` state ! 8  `xor` state ! 9
                         , state ! 10 `xor` state ! 11 `xor` state ! 12 `xor` state ! 13 `xor` state ! 14
                         , state ! 15 `xor` state ! 16 `xor` state ! 17 `xor` state ! 18 `xor` state ! 19
                         , state ! 20 `xor` state ! 21 `xor` state ! 22 `xor` state ! 23 `xor` state ! 24
                         ]
          d = V.map (\x -> c ! ((x - 1) `mod` 5) `xor` rotateL (c ! ((x + 1) `mod` 5)) 1)
                    (V.enumFromN 0 5)


-- can be done using backpermute & update
rhoPi :: V.Vector Word64 -> V.Vector Word64
rhoPi state = V.map (\z -> rotFunc ((div z 5 + 3 * rem z 5) `mod` 5, div z 5)) (V.enumFromN 0 numLanes)
    where rotFunc (x, y) = rotateL (state ! (x * 5 + y)) (rotationConstants ! (x * 5 +  y))


-- The only non-linear component of keccakF
chi :: V.Vector Word64 -> V.Vector Word64
chi b = V.map func (V.enumFromN 0 numLanes)
    where func z = let x = div z 5
                       y = rem z 5
                   in (b ! z) `xor`
                      (complement (b ! (mod (x + 1) 5 * 5 + y)) .&. (b ! (((x + 2) `mod` 5) * 5 + y)))


iota :: Int -> V.Vector Word64 -> V.Vector Word64
iota round state = state // [(0, xor (roundConstants ! round) (V.head state))]
