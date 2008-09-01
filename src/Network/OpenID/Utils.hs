
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
  , addParams
  , parseParams
  , formatParams
  , formatDirectParams
  , readMaybe
  , breaks
  , roll
  , unroll
  , btwoc

    -- * OpenID Defaults
  , defaultModulus
  , openidNS

    -- * MonadLib helpers
  , readM
  ) where

-- Friends
import Network.OpenID.Types

-- Libraries
import Data.Bits
import Data.Char
import Data.List
import Data.Maybe
import Data.Word
import MonadLib
import Network.URI



defaultModulus :: Integer
defaultModulus  = 0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB


-- | Escape for the query string of a URI
escapeParam :: String -> String
escapeParam  = escapeURIString isUnreserved


-- | Add Parameters to a URI
addParams :: Params -> URI -> URI
addParams ps uri = uri { uriQuery = query }
  where
    f (k,v) = (k,v)
    ps' = map f ps
    query = '?' : formatParams (parseParams (uriQuery uri) ++ ps')


-- | Parse OpenID parameters out of a url string
parseParams :: String -> Params
parseParams xs = case break (== '?') xs of
  (_,_:bs) -> map f (breaks (== '&') bs)
  _        -> []
  where
  f ys = case break (== '=') ys of
    (as,_:bs) -> (as, unEscapeString bs)
    (as,[])   -> (as, [])


-- | Format OpenID parameters as a query string
formatParams :: Params -> String
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


openidNS :: String
openidNS  = "http://specs.openid.net/auth/2.0"


-- | Read inside of an Exception monad
readM :: (ExceptionM m e, Read a) => e -> String -> m a
readM e str = case reads str of
  [(x,"")] -> return x
  _        -> raise e
