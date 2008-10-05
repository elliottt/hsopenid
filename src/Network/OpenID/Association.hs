{-# LANGUAGE FlexibleContexts, FlexibleInstances, GeneralizedNewtypeDeriving,
             MultiParamTypeClasses #-}

--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Association
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : 
-- Stability   : 
-- Portability : 
--

module Network.OpenID.Association (
    -- * Association
    associate
  , associate'

    -- * Lower-level interface
  , Assoc, runAssoc, AssocEnv(..)
  , associate_

  , module Network.OpenID.Association.Manager
  , module Network.OpenID.Association.Map
  ) where

-- Friends
import Codec.Binary.Base64
import Codec.Encryption.DH
import Data.Digest.OpenSSL.SHA
import Network.OpenID.Association.Manager
import Network.OpenID.Association.Map
import Network.OpenID.HTTP
import Network.OpenID.Types
import Network.OpenID.Utils

-- Libraries
import Data.Bits
import Data.List
import Data.Maybe
import Data.Time
import Data.Word
import MonadLib
import Network.HTTP hiding (Result)

-- Utilities -------------------------------------------------------------------

-- | Check to see if an AssocType and SessionType pairing is valid.
validPairing :: AssocType -> SessionType -> Bool
validPairing _          NoEncryption = True
validPairing HmacSha256 DhSha256     = True
validPairing HmacSha1   DhSha256     = True
validPairing _          _            = False


-- | Generate parameters for Diffie-Hellman key exchange, based on the provided
--   SessionType.
newSessionTypeParams :: SessionType -> IO (Maybe DHParams)
newSessionTypeParams NoEncryption = return Nothing
newSessionTypeParams st           = newDHParams bits gen
  where
    bits = case st of
      NoEncryption -> 0
      DhSha1       -> 160
      DhSha256     -> 256
    gen = 2 -- for now?


-- | Turn DHParams into a list of key/value pairs that can be sent to a
--   Provider.
dhPairs :: DHParams -> Params
dhPairs dh = [ ("openid.dh_modulus", enci $ dhModulus dh)
             , ("openid.dh_gen", enci $ toInteger $ dhGenerator dh)
             , ("openid.dh_consumer_public", enc $ dhPublicKey dh)
             ]
  where
    enc = encodeRaw True . btwoc
    enci = enc . unroll


-- | Give the hash algorithm for a session type
hash :: SessionType -> [Word8] -> [Word8]
hash NoEncryption = id
hash DhSha1       = sha1
hash DhSha256     = sha256


-- | Get the mac key from a set of Diffie-Hellman parameters, and the public
--   key of the server.
decodeMacKey :: SessionType -> [Word8] -> [Word8] -> DHParams -> [Word8]
decodeMacKey st mac pubKey dh = zipWith xor key mac
  where  key = hash st $ btwoc $ computeKey pubKey dh


-- Interface -------------------------------------------------------------------


-- | Associate with a provider.
--   By default, this tries to use DH-SHA256 and HMAC-SHA256, and falls back to
--   whatever the server recommends, if the Bool parameter is True.
associate :: AssociationManager am
          => am -> Bool -> Resolver IO -> Provider -> IO (Either Error am)
associate am rec res prov = associate' am rec res prov HmacSha256 DhSha256


-- | Associate with a provider, attempting to use the provided association
--   methods.  The Bool specifies whether or not recovery should be attempted
--   upon a failed request.
associate' :: AssociationManager am
           => am -> Bool -> Resolver IO -> Provider -> AssocType -> SessionType
           -> IO (Either Error am)
associate' am rec res prov at st
  = runAssoc (AssocEnv getCurrentTime newSessionTypeParams)
  $ associate_ am rec res prov at st


-- | Association environment
data AssocEnv m = AssocEnv
  { currentTime  :: m UTCTime
  , createParams :: SessionType -> m (Maybe DHParams)
  }


-- | Association monad
newtype Assoc m a = Assoc (ReaderT (AssocEnv m) (ExceptionT Error m) a)
  deriving (Functor,Monad)

instance (Monad m, BaseM m m) => BaseM (Assoc m) m where
  inBase m = Assoc (inBase m)

instance Monad m => ExceptionM (Assoc m) Error where
  raise e = Assoc (raise e)

instance Monad m => ReaderM (Assoc m) (AssocEnv m) where
  ask = Assoc ask


-- | Running a computation in the association monad
runAssoc :: (Monad m, BaseM m m)
         => AssocEnv m -> Assoc m a -> m (Either Error a)
runAssoc env (Assoc m) = runExceptionT (runReaderT env m)


-- | Use the underlying monad to retrieve the current time.
getTime :: BaseM m m => Assoc m UTCTime
getTime  = inBase . currentTime =<< ask


-- | Generate Diffie-Hellman parameters in the underlying monad.
newParams :: BaseM m m => SessionType -> Assoc m (Maybe DHParams)
newParams st = ask >>= \env -> inBase (createParams env st)


-- | A "pure" version of association.  It will run in whatever base monad is
--   provided, layering exception handling over that.
associate_ :: (BaseM m m, Monad m, AssociationManager am)
           => am -> Bool -> Resolver m -> Provider -> AssocType -> SessionType
           -> Assoc m am
associate_ am' recover resolve prov at st = do
  now <- getTime
  let am = expire am' now
  if isJust (findAssociation am prov)
    then return am
    else case validPairing at st of
      True  -> do
        mb_dh <- newParams st
        let body = formatParams
                 $ ("openid.ns", openidNS)
                 : ("openid.mode", "associate")
                 : ("openid.assoc_type", show at)
                 : ("openid.session_type", show st)
                 : maybe [] dhPairs mb_dh
        ersp <- inBase $ resolve $ postRequest (providerURI prov) body
        withResponse ersp $ \rsp -> do
          let ps = parseDirectResponse (rspBody rsp)
          case rspCode rsp of
            (2,0,0) -> handleAssociation am ps mb_dh prov now at st
            (4,0,0)
              | recover   -> recoverAssociation am ps resolve prov at st
              | otherwise ->
                  let m = maybe "" (": " ++) (lookup "error" ps)
                   in raise $ Error $ "unable to associate" ++ m
            _ -> raise $ Error "unexpected HTTP response"
      False -> raise $ Error "invalid association and session type pairing"


-- | Attempt to recover from an association failure
recoverAssociation :: (BaseM m m, Monad m, AssociationManager am)
                   => am -> Params -> Resolver m -> Provider
                   -> AssocType -> SessionType
                   -> Assoc m am
recoverAssociation am ps res prov at st = associate_ am False res prov
  (l at "assoc_type") (l st "session_type")
  where l d k = fromMaybe d (readMaybe =<< lookup k ps)


-- | Handle the response to an associate request.
handleAssociation :: (Monad m, AssociationManager am)
                  => am -> Params -> Maybe DHParams -> Provider -> UTCTime
                  -> AssocType -> SessionType
                  -> Assoc m am
handleAssociation am ps mb_dh prov now at st = do
  ah <- lookupParam "assoc_handle" ps
  ei <- readParam   "expires_in"   ps
  mk <- case (st,mb_dh) of
    (NoEncryption,_) -> decode `fmap` lookupParam "mac_key" ps
    (_,Just dh)      -> do
      mk     <- lookupParam "enc_mac_key"      ps
      pubKey <- lookupParam "dh_server_public" ps
      return $ decodeMacKey st (decode mk) (decode pubKey) dh
    _ -> raise (Error "Diffie-Hellman parameters not generated")
  return $ addAssociation am now prov
         $ Association ei ah mk at
