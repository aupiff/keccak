{-# LANGUAGE OverloadedStrings #-}

import           Crypto.Hash.Keccak
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base16 as BS16

smallKeccak :: BS.ByteString -> BS.ByteString
smallKeccak = keccakHash 1568

message :: BS.ByteString
message = "I am fascinated by Tim May's crypto-anarchy. Unlike the communities traditionally associated with the word 'anarchy', in a crypto-anarchy the government is not temporarily destroyed but permanently forbidden and permanently unnecessary. It's a community where the threat of violence is impotent because violence is impossible, and violence is impossible because its participants cannot be linked to their true names or physical locations.  Until now it's not clear, even theoretically, how such a community could operate. A community is defined by the cooperation of its participants, and efficient cooperation requires a medium of exchange (money) and a way to enforce contracts. Traditionally these services have been provided by the government or government sponsored institutions and only to legal entities. In this article I describe a protocol by which these services can be provided to and by untraceable entities.  I will actually describe two protocols. The first one is impractical, because it makes heavy use of a synchronous and unjammable anonymous broadcast channel. However it will motivate the second, more practical protocol. In both cases I will assume the existence of an untraceable network, where senders and receivers are identified only by digital pseudonyms (i.e. public keys) and every messages is signed by its sender and encrypted to its receiver.  In the first protocol, every participant maintains a (seperate) database of how much money belongs to each pseudonym. These accounts collectively define the ownership of money, and how these accounts are updated is the subject of this protocol."

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
