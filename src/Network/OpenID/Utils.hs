
--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Utils
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : 
-- Stability   : 
-- Portability : 
--

module Network.OpenID.Utils (
    escapeParam
  , parseParams
  , formatParams
  , formatDirectParams
  , readMaybe
  , breaks
  , roll
  , unroll
  , btwoc
  ) where

-- Libraries
import Data.Bits
import Data.Char
import Data.List
import Data.Word
import Network.URI


-- | Escape for the query string of a URI
escapeParam :: String -> String
escapeParam  = escapeURIString isUnreserved


-- | Parse OpenID parameters out of a url string
parseParams :: String -> [(String,String)]
parseParams xs = case break (== '?') xs of
  (_,_:bs) -> map f (breaks (== '&') bs)
  _        -> []
  where
  f ys = case break (== '=') ys of
    (as,_:bs) -> (as, unEscapeString bs)
    (as,[])   -> (as, [])


-- | Format OpenID parameters as a query string
formatParams :: [(String,String)] -> String
formatParams  = concat . intersperse "&" . map f
  where f (x,y) = x ++ "=" ++ escapeParam y


-- | Format parameters for a direct request
formatDirectParams :: [(String,String)] -> String
formatDirectParams  = concatMap f
  where f (x,y) = x ++ ":" ++ y ++ "\n"


-- | Read, maybe.
readMaybe :: Read a => String -> Maybe a
readMaybe str = case reads str of
  [(x,"")] -> Just x
  _        -> Nothing


-- | Break up a string by a predicate.
breaks :: (a -> Bool) -> [a] -> [[a]]
breaks p xs = case break p xs of
  (as,_:bs) -> as : breaks p bs
  (as,_)    -> [as]


roll :: [Word8] -> Integer
roll  = foldr step 0 . reverse
  where step n acc = acc `shiftL` 8 .|. fromIntegral n


unroll :: Integer -> [Word8]
unroll = reverse . unfoldr step
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `shiftR` 8)


btwoc :: [Word8] -> [Word8]
btwoc [] = [0x0]
btwoc bs@(x:_) | testBit x 7 = 0x0 : bs
               | otherwise   =       bs
