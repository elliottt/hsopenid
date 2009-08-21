{-# LANGUAGE FlexibleContexts #-}

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
    -- * General Helpers
    readMaybe
  , breaks
  , split
  , roll
  , unroll
  , btwoc

    -- * OpenID Defaults
  , defaultModulus
  , openidNS

    -- * MonadLib helpers
  , readM
  , lookupParam
  , readParam
  , withResponse
  ) where

-- friends
import Network.OpenID.Types

-- libraries
import Data.Bits
import Data.Char
import Data.List
import Data.Maybe
import Data.Word
import MonadLib
import Network.HTTP
import Network.Stream


-- General Helpers -------------------------------------------------------------

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


-- | Spit a list into a pair, removing the element that caused the predicate to
--   succeed.
split :: (a -> Bool) -> [a] -> ([a],[a])
split p as = case break p as of
  (xs,_:ys) -> (xs,ys)
  pair      -> pair


-- | Build an Integer out of a big-endian list of bytes.
roll :: [Word8] -> Integer
roll  = foldr step 0 . reverse
  where step n acc = acc `shiftL` 8 .|. fromIntegral n


-- | Turn an Integer into a big-endian list of bytes
unroll :: Integer -> [Word8]
unroll = reverse . unfoldr step
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `shiftR` 8)


-- | Pad out a list of bytes to represent a positive, big-endian list of bytes.
btwoc :: [Word8] -> [Word8]
btwoc [] = [0x0]
btwoc bs@(x:_) | testBit x 7 = 0x0 : bs
               | otherwise   =       bs


-- OpenID Defaults -------------------------------------------------------------

-- | The OpenID-2.0 namespace.
openidNS :: String
openidNS  = "http://specs.openid.net/auth/2.0"


-- | Default modulus for Diffie-Hellman key exchange.
defaultModulus :: Integer
defaultModulus  = 0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB


-- MonadLib Helpers ------------------------------------------------------------

-- | Read inside of an Exception monad
readM :: (ExceptionM m e, Read a) => e -> String -> m a
readM e str = case reads str of
  [(x,"")] -> return x
  _        -> raise e


-- | Lookup parameters inside an exception handling monad
lookupParam :: ExceptionM m Error => String -> Params -> m String
lookupParam k ps = maybe err return (lookup k ps)
  where err = raise $ Error $ "field not present: " ++ k


-- | Read a field
readParam :: (Read a, ExceptionM m Error) => String -> Params -> m a
readParam k ps = readM err =<< lookupParam k ps
  where err = Error ("unable to read field: " ++ k)


-- | Make an HTTP request, and run a function with a successful response
withResponse :: ExceptionM m Error
             => Either ConnError (Response String) -> (Response String -> m a) -> m a
withResponse (Left  err) _ = raise $ Error $ show err
withResponse (Right rsp) f = f rsp
