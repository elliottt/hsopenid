
--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Association
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>
-- Stability   : 
-- Portability : 
--

module Network.OpenID.Association (
    -- * Utilities
    assocToParams
  , getHashFunction

    -- * Association
  , associate
  , verifySignature
  , defaultModulus
  , defaultGen
  ) where

-- Friends
import Codec.Binary.Base64
import Network.OpenID.Types
import Network.OpenID.Utils

-- Libraries
import Data.Digest.OpenSSL.HMAC
import Data.List
import Data.Maybe
import Network.URI
import Numeric

import qualified Data.ByteString as B

import Debug.Trace


-- Utility Functions -----------------------------------------------------------

-- | Turn an assoc type into a CryptoHashFunction.
getHashFunction :: AssocType -> CryptoHashFunction
getHashFunction HmacSha1   = sha1
getHashFunction HmacSha256 = sha256


-- | Serialize an association into a form that's suitable for passing as a set
-- of request parameters.
assocToParams :: Association -> [String]
assocToParams assoc = ["openid.assoc_handle=" ++ handle]
  where handle = escapeURIString isUnreserved (assocHandle assoc)


-- Association -----------------------------------------------------------------

defaultModulus :: Integer
defaultModulus  = 0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB


defaultGen :: Integer
defaultGen  = 2


trc x = trace (show x) x


-- | Attempt to associate to a provider.
associate :: Monad m
          => Request m -> AssocRequest -> Provider
          -> m (Result Association)
associate resolve ar ep = do
  let body = formatParams
           $ ("openid.mode", "associate")
           : ("openid.assoc_type", show_AssocType $ arType ar)
           : ("openid.ns", "http://specs.openid.net/auth/2.0")
           : sessionType_to_params (arSessionType ar)
      req  = getProvider ep
  eresp <- resolve req $ trc body
  case eresp of
    Left  err     -> return $ fail err
    Right (_,str) ->
      let split xs = case break (== ':') xs of
            (as,_:bs) -> (as,bs)
            (as,[])   -> (as,[])
          resp = map split $ lines $ trc str
       in case lookup "error" resp of
          Just e  -> fail e
          Nothing -> return $ do
            let f m = maybe (fail m) return
                l k = lookup k resp
            h <- f "assoc_handle" $                    l "assoc_handle"
            t <- f "assoc_type"   $ read_AssocType =<< l "assoc_type"
            e <- f "expires_in"   $ readMaybe      =<< l "expires_in"
            m <- f "mac_key"      $                    l "mac_key"
            return $ Association h t e m


-- Verification ----------------------------------------------------------------

-- | Given an association and a signed message, verify the signature and use
-- a supplied function to build a type.
verifySignature :: Association -> Signed a -> (Params -> Maybe a)
                -> Either String a
verifySignature assoc sig f =
  let fields    = sigFields sig
      params    = sigParams sig
      signature = sigValue  sig
      key       = B.pack $ decode $ assocMacKey assoc
      message   = generateMessage fields params
      hash      = getHashFunction (assocType assoc)
      err       = Left "Unable to parse params"
   in case readHex (unsafeHMAC hash key message) of
        [(x,"")] | unroll x == signature -> maybe err Right (f params)
        _                                -> Left "Signatures don't match"


-- | Given a list of fields and a set of parameters, generate the message part
-- of a signature.
generateMessage :: [String] -> Params -> B.ByteString
generateMessage fields params = B.pack
                              $ map (toEnum . fromEnum)
                              $ concatMap f
                              $ filter p params
  where
    f (key,value) | "openid." `isPrefixOf` key = fmt (drop 7 key) value
                  | otherwise                  = fmt key value
      where fmt k v = k ++ ":" ++ v ++ "\n"
    p (k,_) = k `elem` fields'
      where fields' = map ("openid." ++) fields
