{-# LANGUAGE FlexibleContexts #-}

--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Authentication
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>
-- Stability   :
-- Portability :
--

module Network.OpenID.Authentication (
    -- * Types
    CheckIdMode(..)

    -- * Authentication
  , authenticationURI
  , verifyAuthentication
  ) where

-- friends
import Codec.Binary.Base64
import Network.OpenID.Association.Manager
import Network.OpenID.HTTP
import Network.OpenID.Types
import Network.OpenID.Utils

-- libraries
import Data.List
import MonadLib
import Network.HTTP
import Network.URI
import Numeric

import qualified Data.ByteString as BS
import qualified Data.Digest.OpenSSL.HMAC as HMAC


--------------------------------------------------------------------------------
-- Types

data CheckIdMode = Immediate | Setup

instance Show CheckIdMode where
  show Immediate = "checkid_immediate"
  show Setup     = "checkid_setup"

instance Read CheckIdMode where
  readsPrec _ s | "checkid_immediate" `isPrefixOf` s = [(Immediate, drop 17 s)]
                | "checkid_setup"     `isPrefixOf` s = [(Setup, drop 13 s)]
                | otherwise                          = []

--------------------------------------------------------------------------------
-- Utilities

-- | Get the mac hash type
macHash :: AssocType -> HMAC.CryptoHashFunction
macHash HmacSha1   = HMAC.sha1
macHash HmacSha256 = HMAC.sha256


-- | Parse a provider within the Result monad
parseProvider' :: ExceptionM m Error => String -> m Provider
parseProvider' = maybe err return . parseProvider
  where err = raise (Error "unable to parse openid.op_endpoint")


-- | Get the signed fields from a set of parameters
getSignedFields :: ExceptionM m Error => [String] -> Params -> m Params
getSignedFields ks ps = maybe err return (mapM lkp ks)
  where
    err = raise (Error "not all signed parameters present")
    lkp k = (,) k `fmap` lookup ("openid." ++ k) ps


--------------------------------------------------------------------------------
-- Authentication

-- | Generate an authentication URL
authenticationURI :: AssociationManager am
                  => am -> CheckIdMode -> Provider -> Identifier -> ReturnTo
                  -> Maybe Realm -> URI
authenticationURI am mode prov ident rt mb_realm =
  addParams params (providerURI prov)
  where
    params = [ ("openid.ns", openidNS)
             , ("openid.mode", show mode)
             , ("openid.claimed_id", getIdentifier ident)
             , ("openid.identity", getIdentifier ident)
             , ("openid.return_to", rt)
             ] ++ ah ++
             maybe [] (\r -> [("openid.realm", r)]) mb_realm
    ah = case findAssociation am prov of
      Nothing -> []
      Just a  -> [("openid.assoc_handle", assocHandle a)]


-- | Verify a signature on a set of params.
verifyAuthentication :: AssociationManager am
                     => am -> Params -> ReturnTo -> Resolver
                     -> IO (Either Error ())
verifyAuthentication am ps rto resolve =
  runExceptionT $ do
    u <- lookupParam "openid.return_to" ps
    unless (u == rto) $ raise $ Error $ "invalid return path: " ++ u
    prov <- parseProvider' =<< lookupParam "openid.op_endpoint" ps
    case findAssociation am prov of
      Nothing    -> verifyDirect ps prov resolve
      Just assoc -> verifyWithAssociation ps assoc


-- | Verify an assertion directly
verifyDirect :: Params -> Provider -> Resolver -> ExceptionT Error IO ()
verifyDirect ps prov resolve = do
  let body = formatParams
           $ ("openid.mode","check_authentication")
           : filter (\p -> fst p /= "openid.mode") ps
  ersp <- inBase $ resolve Request
    { rqURI     = providerURI prov
    , rqMethod  = POST
    , rqHeaders =
      [ Header HdrContentLength $ show $ length body
      , Header HdrContentType "application/x-www-form-urlencoded"
      ]
    , rqBody    = body
    }
  withResponse ersp $ \rsp -> do
    let rps = parseDirectResponse (rspBody rsp)
    case lookup "is_valid" rps of
      Just "true" -> return ()
      _           -> raise (Error "invalid authentication request")


-- | Verify with an association
verifyWithAssociation :: Params -> Association -> ExceptionT Error IO ()
verifyWithAssociation ps a = do
  mode <- lookupParam "openid.mode" ps
  unless (mode == "id_res") $ raise $ Error $ "unexpected openid.mode: " ++ mode
  sigParams <- breaks (',' ==) `fmap` lookupParam "openid.signed" ps
  sig <- decode `fmap` lookupParam "openid.sig" ps
  sps <- getSignedFields sigParams ps
  let h    = macHash (assocType a)
      msg  = map (toEnum . fromEnum) (formatDirectParams sps)
      mc   = HMAC.unsafeHMAC h (BS.pack (assocMacKey a)) (BS.pack msg)
      sig' = case readHex mc of
        [(x,"")] -> unroll x
        _        -> []
  unless (sig' == sig) $ raise $ Error "invalid signature"
