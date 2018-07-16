module Crypto.Hash.Keccak
    ( -- * Standard keccak hash functions
      keccak224
    , keccak256
    , keccak384
    , keccak512
      -- * Standard sha3 hash functions
    , sha3_512
    , sha3_384
    , sha3_256
    , sha3_224
      -- * Building blocks of a keccak sponge hash function
    , keccakHash
    , paddingKeccak
    , absorb
    , toBlocks
    , squeeze
    ) where

import           Data.Bits
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Lazy       as LBS
import           Data.Word

type State = [[Word64]]

emptyState :: State
emptyState = replicate 5 (replicate 5 0)

--------------------------------------------------------
-- Constants used in KeccakF[1600] permutation
--------------------------------------------------------

roundConstants :: [Word64]
roundConstants = [ 0x0000000000000001, 0x0000000000008082, 0x800000000000808A
                 , 0x8000000080008000, 0x000000000000808B, 0x0000000080000001
                 , 0x8000000080008081, 0x8000000000008009, 0x000000000000008A
                 , 0x0000000000000088, 0x0000000080008009, 0x000000008000000A
                 , 0x000000008000808B, 0x800000000000008B, 0x8000000000008089
                 , 0x8000000000008003, 0x8000000000008002, 0x8000000000000080
                 , 0x000000000000800A, 0x800000008000000A, 0x8000000080008081
                 , 0x8000000000008080, 0x0000000080000001, 0x8000000080008008 ]

rotationConstants :: [[Int]]
rotationConstants = [ [  0, 36,  3, 41, 18 ]
                    , [  1, 44, 10, 45,  2 ]
                    , [ 62,  6, 43, 15, 61 ]
                    , [ 28, 55, 25, 21, 56 ]
                    , [ 27, 20, 39,  8, 14 ]
                    ]


--------------------------------------------------------
-- Keccak and SHA3 hash functions
--------------------------------------------------------

keccakHash :: Int -> BS.ByteString -> BS.ByteString
keccakHash rate = squeeze outputBytes . absorb rate
                                      . toBlocks bitrateBytes
                                      . paddingKeccak bitrateBytes
    where bitrateBytes = div rate 8
          outputBytes = div (1600 - rate) 16


sha3Hash :: Int -> BS.ByteString -> BS.ByteString
sha3Hash rate = squeeze outputBytes . absorb rate
                                      . toBlocks bitrateBytes
                                      . paddingSha3 bitrateBytes
    where bitrateBytes = div rate 8
          outputBytes = div (1600 - rate) 16


keccak512 :: BS.ByteString -> BS.ByteString
keccak512 = keccakHash 576


keccak384 :: BS.ByteString -> BS.ByteString
keccak384 =  keccakHash 832


keccak256 :: BS.ByteString -> BS.ByteString
keccak256 = keccakHash 1088


keccak224 :: BS.ByteString -> BS.ByteString
keccak224 = keccakHash 1152


sha3_512 :: BS.ByteString -> BS.ByteString
sha3_512 = sha3Hash 576


sha3_384 :: BS.ByteString -> BS.ByteString
sha3_384 = sha3Hash 832


sha3_256 :: BS.ByteString -> BS.ByteString
sha3_256 = sha3Hash 1088


sha3_224 :: BS.ByteString -> BS.ByteString
sha3_224 = sha3Hash 1152


--------------------------------------------------------
-- Padding functions
--------------------------------------------------------

-- | Multi-rate padding appends at least 2 bits and at most the number of bits
-- in a block plus one.
multiratePadding :: Int -> Word8 -> BS.ByteString -> [Word8]
multiratePadding bitrateBytes padByte input = BS.unpack . BS.append input $ if padlen == 1
    then BS.pack [0x81]
    else BS.pack $ padByte : replicate (padlen - 2) 0x00 ++ [0x80]
    where padlen = bitrateBytes - mod (BS.length input) bitrateBytes


paddingKeccak :: Int -> BS.ByteString -> [Word8]
paddingKeccak bitrateBytes = multiratePadding bitrateBytes 0x1


paddingSha3 :: Int -> BS.ByteString -> [Word8]
paddingSha3 bitrateBytes = multiratePadding bitrateBytes 0x6


----------------------------------------------------
-- Sponge function primitives
----------------------------------------------------

toBlocks :: Int -> [Word8] -> [[Word64]]
toBlocks _ [] = []
toBlocks sizeInBytes input = let (a, b) = splitAt sizeInBytes input
                             in toLanes a : toBlocks sizeInBytes b
    where toLanes :: [Word8] -> [Word64]
          toLanes [] = []
          toLanes octets = let (a, b) = splitAt 8 octets
                           in toLane a : toLanes b
          toLane :: [Word8] -> Word64
          toLane octets = foldl1 xor $ zipWith (\offset octet -> shiftL (fromIntegral octet) (offset * 8)) [0..7] octets

-- | Absorbtion phase
-- for each block Pi in P
--   S[x,y] = S[x,y] xor Pi[x+5*y],          for (x,y) such that x+5*y < r/w
--   S = Keccak-f[r+c](S)
absorb :: Int -> [[Word64]] -> State
absorb rate = foldl (absorbBlock rate) emptyState

absorbBlock :: Int -> State -> [Word64] -> State
absorbBlock rate state input = keccakF state'
    where w = 64 -- lane size
          state' = [ [ if x + 5 * y < div rate w
                            then ((state !! x) !! y) `xor` (input !! (x + 5 * y))
                            else (state !! x) !! y
                        | y <- [0..4] ]
                            | x <- [0..4] ]


--  | Squeezing phase
--  Z = empty string
--  while output is requested
--    Z = Z || S[x,y],                  for (x,y) such that x+5*y < r/w
--    S = Keccak-f[r+c](S)
--    TODO handle longer outputs
squeeze :: Int -> State -> BS.ByteString
squeeze len = BS.pack . take len . stateToBytes


stateToBytes :: State -> [Word8]
stateToBytes state = concat [ laneToBytes (state !! x !!  y) | y <- [0..4] , x <- [0..4] ]


laneToBytes :: Word64 -> [Word8]
laneToBytes word = fmap (\x -> fromIntegral (shiftR word (x * 8) .&. 0xFF)) [0..7]


-------------------------------------------------------------
-- KeccakF permutation & constituent primatives
-------------------------------------------------------------


keccakF :: State -> State
keccakF state = foldl (\s r -> iota r . chi . rhoPi $ theta s) state [0 .. (rounds - 1)]
    where rounds = 24

-- | θ step
-- C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
-- D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
-- A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)
theta :: State -> State
theta state = [ [ ((state !! x) !! y) `xor` (d !! x)
                    | y <- [0..4] ]
                        | x <- [0..4] ]
    where c = [ foldl1 xor [ (state !! x) !! y
                    | y <- [0..4] ]
                        | x <- [0..4] ]
          d = [ c !! ((x - 1) `mod` 5) `xor` rotateL (c !! ((x + 1) `mod` 5)) 1 | x <- [0..4] ]


-- | ρ and π steps
-- B[y,2*x+3*y] = rot(A[x,y], r[x,y]),        for (x,y) in (0…4,0…4)
rhoPi :: State -> [[Word64]]
rhoPi state = fmap (fmap rotFunc) [ [ ((x + 3 * y) `mod` 5, x) | y <- [0..4] ] | x <- [0..4] ]
    where rotFunc (x, y) = rotateL ((state !! x) !! y) ((rotationConstants !! x) !! y)


-- | χ step
-- A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)
chi :: [[Word64]] -> State
chi b = [ [ ((b !! x) !! y) `xor` (complement ((b !! ((x + 1) `mod` 5)) !! y) .&. ((b !! ((x + 2) `mod` 5)) !! y))
                    | y <- [0..4] ]
                        | x <- [0..4] ]


-- | ι step
-- A[0,0] = A[0,0] xor RC
iota :: Int -> State -> State
iota round ((first : rest) : restRows) = (xor (roundConstants !! round) first : rest) : restRows
