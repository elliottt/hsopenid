{-# LANGUAGE FlexibleContexts #-}

--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.AssociationManager
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : 
-- Stability   : 
-- Portability : 
--

module Network.OpenID.AssociationManager (
    -- * Types
    AssociationManager(..)
  , AssociationMap
  , emptyAssociationMap

    -- * Association
  , associate
  , associate'
  , verifySignature
  ) where

-- Friends
import Codec.Binary.Base64
import Codec.Encryption.DH
import Data.Digest.OpenSSL.SHA
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
import Numeric

import qualified Data.ByteString as BS
import qualified Data.Digest.OpenSSL.HMAC as HMAC
import qualified Data.Map as Map

--------------------------------------------------------------------------------
-- Types

-- | Manage pairs of Providers and Associations.
class AssociationManager am where
  -- | Find an association.
  findAssociation :: am -> Provider -> Maybe Association

  -- | Add a new association, and set its expiration to be relative to the "now"
  --   parameter passed in.
  addAssociation :: am -> UTCTime -> Provider -> Association -> am

  -- | Expire associations in the manager that are older than the supplied "now"
  --   parameter.
  expire :: am -> UTCTime -> am

  -- | Export all associations, and their expirations
  exportAssociations :: am -> [(String,UTCTime,Association)]


-- | A simple association manager based on Data.Map
newtype AssociationMap = AM (Map.Map String (UTCTime,Association))
  deriving Show

instance AssociationManager AssociationMap where
  findAssociation (AM m) p = snd `fmap` Map.lookup (showProvider p) m

  addAssociation (AM m) now p a = AM (Map.insert (showProvider p) (expire,a) m)
    where expire = addUTCTime (toEnum (assocExpiresIn a)) now

  expire (AM m) now = AM (Map.filter ((now >) . fst) m)

  exportAssociations (AM m) = map f (Map.toList m)
    where f (p,(t,a)) = (p,t,a)


-- | An empty association map.
emptyAssociationMap :: AssociationMap
emptyAssociationMap  = AM Map.empty


--------------------------------------------------------------------------------
-- Utilities

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


-- | Get the mac hash type
macHash :: AssocType -> HMAC.CryptoHashFunction
macHash HmacSha1   = HMAC.sha1
macHash HmacSha256 = HMAC.sha256


-- | Make an HTTP request, and run a function with a successful response
withResponse :: (ExceptionM m Error, BaseM m IO)
             => Either ConnError Response -> (Response -> m a) -> m a
withResponse (Left  err) _ = raise $ Error $ show err
withResponse (Right rsp) f = f rsp


-- | Get the mac key from a set of Diffie-Hellman parameters, and the public
--   key of the server.
decodeMacKey :: SessionType -> [Word8] -> [Word8] -> DHParams -> [Word8]
decodeMacKey st mac pubKey dh = zipWith xor key mac
  where  key = hash st $ btwoc $ computeKey pubKey dh


-- | Lookup parameters inside an exception handling monad
lookupParam :: ExceptionM m Error => String -> Params -> m String
lookupParam k ps = maybe err return (lookup k ps)
  where err = raise $ Error $ "field not present: " ++ k


-- | Read a field
readParam :: (Read a, ExceptionM m Error) => String -> Params -> m a
readParam k ps = readM err =<< lookupParam k ps
  where err = Error ("unable to read field: " ++ k)


--------------------------------------------------------------------------------
-- Interface


-- | Associate with a provider.
--   By default, this tries to use DH-SHA256 and HMAC-SHA256, and falls back to
--   whatever the server recommends, if the Bool parameter is True.
associate :: AssociationManager am
          => am -> Bool -> Resolver -> Provider -> IO (Either Error am)
associate am rec res prov = associate' am rec res prov HmacSha256 DhSha256


-- | Associate with a provider, attempting to use the provided association
--   methods.  The Bool specifies whether or not recovery should be attempted
--   upon a failed request.
associate' :: AssociationManager am
           => am -> Bool -> Resolver -> Provider -> AssocType -> SessionType
           -> IO (Either Error am)
associate' am' recover resolve prov at st = do
  now <- getCurrentTime
  let am = expire am' now
  if isJust (findAssociation am prov)
    then return (Right am)
    else runExceptionT $ case validPairing at st of
      False -> raise $ Error "invalid association and session type pairing"
      True  -> do
        mb_dh <- inBase (newSessionTypeParams st)
        let body = formatParams
                 $ ("openid.ns", openidNS)
                 : ("openid.mode", "associate")
                 : ("openid.assoc_type", show at)
                 : ("openid.session_type", show st)
                 : maybe [] dhPairs mb_dh
        ersp <- inBase $ resolve Request
          { rqMethod  = POST
          , rqURI     = providerURI prov
          , rqHeaders =
            [ Header HdrContentLength $ show $ length body
            , Header HdrContentType "application/x-www-form-urlencoded"
            ]
          , rqBody    = body
          }
        withResponse ersp $ \rsp -> do
          let ps = parseDirectResponse (rspBody rsp)
          case rspCode rsp of
            (2,0,0) -> do
              now <- inBase getCurrentTime
              handleAssociation am ps mb_dh prov now at st
            (4,0,0)
              | recover ->
                  let f = either raise return
                      m = inBase (recoverAssociation am ps resolve prov at st)
                   in f =<< m
              | otherwise ->
                  let m = maybe "" (": " ++) (lookup "error" ps)
                   in raise $ Error $ "unable to associate" ++ m
            _ -> raise $ Error "unexpected HTTP response"


-- | Attempt to recover from an association failure
recoverAssociation :: AssociationManager am
                   => am -> Params -> Resolver -> Provider
                   -> AssocType -> SessionType
                   -> IO (Either Error am)
recoverAssociation am ps res prov at st = associate' am False res prov
  (l at "assoc_type") (l st "session_type")
  where l d k = fromMaybe d (readMaybe =<< lookup k ps)


-- | Handle the response to an associate request.
handleAssociation :: (Functor m, ExceptionM m Error, AssociationManager am)
                  => am -> Params -> Maybe DHParams -> Provider -> UTCTime
                  -> AssocType -> SessionType
                  -> m am
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
  return $ addAssociation am now prov Association
    { assocExpiresIn = ei
    , assocHandle    = ah
    , assocMacKey    = mk
    , assocType      = at
    }


-- | Verify a signature on a set of params.
verifySignature :: AssociationManager am => am -> Params -> Either Error ()
verifySignature am ps = runId $ runExceptionT $ do
  mode <- lookupParam "openid.mode" ps
  unless (mode == "id_res") $ raise $ Error $ "unexpected openid.mode: " ++ mode
  sigParams <- breaks (',' ==) `fmap` lookupParam "openid.signed" ps
  p   <- parseProvider' =<< lookupParam "openid.op_endpoint" ps
  sig <- decode `fmap` lookupParam "openid.sig" ps
  sps <- getSignedFields sigParams ps
  a   <- let err = raise $ Error $ "no association for: " ++ show p
          in maybe err return (findAssociation am p)
  let h    = macHash (assocType a)
      msg  = map (toEnum . fromEnum) (formatDirectParams sps)
      mc   = HMAC.unsafeHMAC h (BS.pack (assocMacKey a)) (BS.pack msg)
      sig' = case readHex mc of
        [(x,"")] -> unroll x
        _        -> []
  unless (sig' == sig) $ raise $ Error "invalid signature"


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
