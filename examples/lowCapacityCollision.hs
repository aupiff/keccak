{-# LANGUAGE OverloadedStrings #-}

import           Crypto.Hash.Keccak
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base16 as BS16

smallKeccak :: BS.ByteString -> BS.ByteString
smallKeccak = keccakHash 1568

message :: BS.ByteString
message = "In the context of cryptography, sponge functions provide a particular way to generalize hash functions to more general functions whose output length is arbitrary. A sponge func- tion instantiates the sponge construction, which is a simple iterated construction building a variable-length input variable-length output function based on a fixed length permutation (or transformation). With this interface, a sponge function can also be used as a stream ci- pher, hence covering a wide range of functionality with hash functions and stream ciphers as particular points.  From a theoretical point of view, sponge functions model in a very simple way the finite memory any concrete construction has access to. A random sponge function is as strong as a random oracle, except for the effects induced by the finite memory. This model can thus be used as an alternative to the random oracle model for expressing security claims.  From a more practical point of view, the sponge construction and its sister construction, called the duplex construction, can be used to implement a large spectrum of the symmetric cryptography functionality. This includes hashing, reseedable pseudo random bit sequence generation, key derivation, encryption, message authentication code (MAC) computation and authenticated encryption. This provides users with a lot of functionality from a single fixed permutation, hence making the implementation easier. The designers of cryptographic primitives may also find it advantageous to develop a strong permutation without worrying about other components such as the key schedule of a block cipher."

hashImage :: BS.ByteString
hashImage = smallKeccak message

incrementByteString :: BS.ByteString -> BS.ByteString
incrementByteString bs = if newHead == 32 then BS.cons newHead (incrementByteString (BS.tail bs))
                            else BS.cons newHead (BS.tail bs)
    where newHead = max 32 $ (1 + BS.head bs) `mod` 127

firstCollision :: (Int, BS.ByteString)
firstCollision = head . dropWhile ((hashImage /=) . smallKeccak . snd) . drop 1 $
                zip [0..] (iterate incrementByteString message)

main :: IO ()
main = do let collision = firstCollision
          putStrLn $ "Collision found after checking " ++ show (fst collision) ++ " inputs."
          print $ snd collision
          print message
          print . BS16.encode $ hashImage
          print . BS16.encode . smallKeccak $ snd collision
