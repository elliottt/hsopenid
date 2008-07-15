
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
  , readMaybe
  , breaks
  , unroll
  ) where

-- Libraries
import Data.Bits
import Data.List
import Data.Word
import Network.URI


-- | Escape for the query string of a URI
escapeParam :: String -> String
escapeParam  = escapeURIString isUnreserved


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


unroll :: Integer -> [Word8]
unroll = reverse . unfoldr step
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `shiftR` 8)

