{-# LANGUAGE OverloadedStrings #-}

module Test.Parse.KAT where

import           Control.Monad          (void)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.Text              as T
import qualified Data.Text.Encoding     as T
import           Data.Text.IO           as T
import           Text.Parsec
import           Text.Parsec.Text
import           Text.Parsec.Expr

type TestFile = [KAT]

data KAT = KAT { length  :: Int
               , message :: BS.ByteString
               , digest  :: BS.ByteString
               } deriving Show

parseTestFile :: Parser TestFile
parseTestFile = skipMany (commentLine <|> blankLine) *> many1 parseKat

commentLine :: Parser ()
commentLine = void $ char '#' *> manyTill anyChar endOfLine

blankLine :: Parser ()
blankLine = void endOfLine

parseKat :: Parser KAT
parseKat = do len <- string "Len = " *> many1 digit <* endOfLine
              msg <- string "Msg = " *> many1 hexDigit <* endOfLine
              digest <- string "MD = " *> many1 hexDigit <* endOfLine
              skipMany (commentLine <|> blankLine)
              let parsedLen = read len
              pure $ KAT parsedLen (BS.take parsedLen $ bytesDecode msg)
                                   (bytesDecode digest)

bytesDecode :: String -> BS.ByteString
bytesDecode = fst . BS16.decode . T.encodeUtf8 . T.pack

parseFromFile :: Parsec T.Text () a -> FilePath -> IO (Either ParseError a)
parseFromFile p fname = do
    input <- T.readFile fname
    return (runParser p () fname input)
