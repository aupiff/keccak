module Crypto.Hash.Keccak where

import qualified Data.ByteString            as BS
import qualified Data.ByteString.Conversion as BSC
import qualified Data.ByteString.Lazy       as LBS
import           Data.Word
import           Data.Bits

type State = [[Word64]]

emptyState :: State
emptyState = replicate 5 (replicate 5 0)

roundConstants = [ 0x0000000000000001, 0x0000000000008082, 0x800000000000808A
                 , 0x8000000080008000, 0x000000000000808B, 0x0000000080000001
                 , 0x8000000080008081, 0x8000000000008009, 0x000000000000008A
                 , 0x0000000000000088, 0x0000000080008009, 0x000000008000000A
                 , 0x000000008000808B, 0x800000000000008B, 0x8000000000008089
                 , 0x8000000000008003, 0x8000000000008002, 0x8000000000000080
                 , 0x000000000000800A, 0x800000008000000A, 0x8000000080008081
                 , 0x8000000000008080, 0x0000000080000001, 0x8000000080008008 ]

paddingKeccak :: BS.ByteString -> [Word8]
paddingKeccak = multiratePadding 0x1


paddingSha3 :: BS.ByteString -> [Word8]
paddingSha3 = multiratePadding 0x6

multiratePadding :: Word -> BS.ByteString -> [Word8]
multiratePadding pad input = BS.unpack . BS.append input $ if padlen == 1
    then BS.pack [0x81]
    else BS.pack $ 0x01 : replicate (padlen - 2) 0x00 ++ [0x80]
    where bitRateBytes = 136
          -- TODO: modulo bitRateBytes?
          usedBytes = BS.length input
          padlen = bitRateBytes - mod usedBytes bitRateBytes

-- r (bitrate) = 1088
-- c (capacity) = 512
keccak256 :: BS.ByteString -> BS.ByteString
keccak256 = squeeze 256 . foldl absorb emptyState . toBlocks 136 . paddingKeccak


-- Sized inputs to this?
toBlocks :: Int -> [Word8] -> [[Word64]]
toBlocks _ [] = []
toBlocks sizeInBytes input = let (a, b) = splitAt sizeInBytes input
                             in toLanes a : toBlocks sizeInBytes b
    where toLanes :: [Word8] -> [Word64]
          toLanes [] = []
          toLanes octets = let (a, b) = splitAt 8 octets
                           in toLane a : toLanes b
          toLane :: [Word8] -> Word64
          toLane octets = foldl1 xor $ zipWith (\offset octet -> shift (fromIntegral octet) (offset * 8))  [1..8] octets


absorb :: State -> [Word64] -> State
absorb state input = keccakF state'
    where r = 1088
          w = 64
          state' = [ [ if x + 5 * y < div r w then ((state !! x) !! y) .|. input !! (x + 5 * y) else (state !! x) !! y | x <- [0..4]  ] |  y <- [0..4] ]

--   for each block Pi in P
--     S[x,y] = S[x,y] xor Pi[x+5*y],          for (x,y) such that x+5*y < r/w
--     S = Keccak-f[r+c](S)


squeeze :: Int -> State -> BS.ByteString
squeeze len state = LBS.toStrict . BSC.toByteString . BSC.List . take 4 $ head state

--  # Squeezing phase
--  Z = empty string
--  while output is requested
--    Z = Z || S[x,y],                        for (x,y) such that x+5*y < r/w
--    S = Keccak-f[r+c](S)

keccakF :: State -> State
keccakF = id
