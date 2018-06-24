module Test.Parse.KAT where

import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.Text              as T
import qualified Data.Text.Encoding     as T
import           Text.Parsec
import           Text.Parsec.Text
import           Text.Parsec.Expr

type TestFile = [KAT]

data KAT = KAT { length  :: Integer
               , message :: BS.ByteString
               , digest  :: BS.ByteString
               }

parseTestFile :: Parser TestFile
parseTestFile = skipMany commentLine *> many1 parseKat

commentLine :: Parser ()
commentLine = char '#' *> manyTill anyChar endOfLine *> return ()

parseKat :: Parser KAT
parseKat = do len <- string "Len = " *> many1 digit
              msg <- string "Msg = " *> many1 hexDigit
              digest <- string "MD = " *> many1 hexDigit
              return $ KAT (read len) (bytesDecode msg)
                                      (bytesDecode digest)

bytesDecode :: String -> BS.ByteString
bytesDecode = fst . BS16.decode . T.encodeUtf8 . T.pack
