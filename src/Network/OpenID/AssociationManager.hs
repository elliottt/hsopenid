
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
import Data.Digest.OpenSSL.SHA
import DiffieHellman
import Network.OpenID.Response
import Network.OpenID.Types
import Network.OpenID.Utils

-- Libraries
import Control.Monad
import Data.Bits
import Data.List
import Data.Time
import Data.Word
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


-- | A simple association manager based on Data.Map
newtype AssociationMap = AM (Map.Map String (UTCTime,Association))
  deriving Show

instance AssociationManager AssociationMap where
  findAssociation (AM m) p = snd `fmap` Map.lookup (showProvider p) m
  addAssociation (AM m) now p a = AM (Map.insert (showProvider p) (expire,a) m)
    where expire = addUTCTime (toEnum (assocExpiresIn a)) now
  expire (AM m) now = AM (Map.filter ((now >) . fst) m)


-- | An empty association map.
emptyAssociationMap :: AssociationMap
emptyAssociationMap  = AM Map.empty


--------------------------------------------------------------------------------
-- Utilities

-- | Check to see if an AssocType and SessionType pairing is valid.
validPairing :: AssocType -> SessionType -> Bool
validPairing _          NoEncryption = True
validPairing HmacSha256 DhSha256 = True
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
withResponse :: Either ConnError Response -> (Response -> IO (Result a))
             -> IO (Result a)
withResponse (Left  err) _ = return $ Error $ show err
withResponse (Right rsp) f = f rsp


-- | Get the mac key from a set of Diffie-Hellman parameters, and the public
--   key of the server.
decodeMacKey :: SessionType -> [Word8] -> [Word8] -> DHParams -> [Word8]
decodeMacKey st mac pubKey dh = zipWith xor key mac
  where  key = hash st $ btwoc $ computeKey pubKey dh


--------------------------------------------------------------------------------
-- Interface


-- | Associate with a provider.
--   By default, this tries to use DH-SHA256 and HMAC-SHA256, and falls back to
--   whatever the server recommends.
associate :: AssociationManager am
          => am -> Resolver -> Provider -> IO (Result am)
associate am res prov = associate' am res prov HmacSha256 DhSha256


-- | Associate with a provider, attempting to use the provided association
--   methods.
associate' :: AssociationManager am
           => am -> Resolver -> Provider -> AssocType -> SessionType
           -> IO (Result am)
associate' am resolve prov at st
  | not (validPairing at st) =
      return $ Error "Invalid association and session type pairing"
  | otherwise = do
    mb_dh <- newSessionTypeParams st
    let err = return . Error
        body = formatParams
             $ ("openid.ns", openidNS)
             : ("openid.mode", "associate")
             : ("openid.assoc_type", show at)
             : ("openid.session_type", show st)
             : maybe [] dhPairs mb_dh
        cl = show (length body)
    ersp <- resolve Request
      { rqMethod  = POST
      , rqURI     = providerURI prov
      , rqHeaders = [ Header HdrContentLength cl ]
      , rqBody    = body
      }
    withResponse ersp $ \rsp -> case rspCode rsp of
      (2,0,0) -> do
        let ps = parseDirectResponse (rspBody rsp)
        now <- getCurrentTime
        -- XXX: this needs to handle the case where the server can't do
        --      the requested type of session/association.
        guardResponse ps $ return $ do
          let l k = maybeToResult ("Field not present in response: " ++ k)
                    (lookup k ps)
          ah <- l "assoc_handle"
          ei <- readResult =<< l "expires_in"
          mk <- case (st,mb_dh) of
            (NoEncryption,_) -> decode `fmap` l "mac_key"
            (_,Just dh)      -> do
              mk     <- l "enc_mac_key"
              pubKey <- l "dh_server_public"
              return $ decodeMacKey st (decode mk) (decode pubKey) dh
            _ -> Error "Diffie-Hellman parameters not generated"
          return $ addAssociation am now prov Association
            { assocExpiresIn = ei
            , assocHandle    = ah
            , assocMacKey    = mk
            , assocType      = at
            }
      _ -> err "HTTP request failure"


-- | Verify a signature on a set of params.
verifySignature :: AssociationManager am => am -> Params -> Result ()
verifySignature am ps = do
  let l k = maybeToResult ("field not present: " ++ k)
            (lookup k ps)
  mode <- l "openid.mode"
  when (mode /= "id_res") $ fail $ "unexpected openid.mode: " ++ mode
  mb_p <- l "openid.op_endpoint"
  case parseProvider mb_p of
    Nothing -> fail "unable to parse openid.op_endpoint"
    Just p  -> do
      sigParams <- breaks (',' ==) `fmap` l "openid.signed"
      sig <- decode `fmap` l "openid.sig"
      let f k v  = (k,v)
          mb_sps = mapM (\k -> f k `fmap` lookup ("openid." ++ k) ps) sigParams
      case mb_sps of
        Nothing  -> fail "Not all signed parameters present"
        Just sps -> case findAssociation am p of
          Nothing -> fail $ "No association present for " ++ show p
          Just a  ->
            let h = macHash (assocType a)
                msg = map (toEnum . fromEnum) $ formatDirectParams sps
                mc = HMAC.unsafeHMAC h (BS.pack $ assocMacKey a) (BS.pack msg)
                sig' = case readHex mc of
                  [(x,"")] -> unroll x
                  _        -> []
             in when (sig' /= sig) $ fail "invalid signature"
