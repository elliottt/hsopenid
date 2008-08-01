{-# LANGUAGE EmptyDataDecls #-}

--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Types
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>Association.hs
-- Stability   : 
-- Portability : 
--

module Network.OpenID.Types where

-- Friends
import Codec.Binary.Base64
import Data.Digest.OpenSSL.SHA
import DiffieHellman
import Network.OpenID.Utils

-- Libraries
import Control.Monad
import Data.Bits
import Data.Word
import Network.HTTP hiding (Result)


data YADIS
data HTML


type Resolver m t = String -> m (Either String ([Header],String))


type Request m = String -> String -> m (Either String ([Header],String))


newtype Provider   = Provider   { getProvider   :: String } deriving (Eq,Show)
newtype Identifier = Identifier { getIdentifier :: String } deriving (Eq,Show)

-- Result Monad ----------------------------------------------------------------

data Result a = Error String | Result a deriving Show

-- | Turn a maybe into a result, using the provided error message in the case of
-- a Nothing
maybeToResult :: String -> Maybe a -> Result a
maybeToResult _   (Just a) = Result a
maybeToResult err Nothing  = Error err

instance Functor Result where
  fmap f (Result r) = Result (f r)
  fmap _ (Error  e) = Error e

instance Monad Result where
  return         = Result
  Error  e >>= _ = Error e
  Result a >>= f = f a
  fail           = Error

instance MonadPlus Result where
  mzero = Error "mzero"
  mplus a@(Result _) _ = a
  mplus   (Error  _) b = b

-- Request Parameters ----------------------------------------------------------

type Params = [(String,String)]


-- Associations ----------------------------------------------------------------


data AssocType = HmacSha1 | HmacSha256
  deriving Show

-- | Read an association type out of a string.
read_AssocType :: String -> Maybe AssocType
read_AssocType "HMAC-SHA1"   = Just HmacSha1
read_AssocType "HMAC-SHA256" = Just HmacSha256
read_AssocType _             = Nothing

-- | Show an association type.
show_AssocType :: AssocType -> String
show_AssocType HmacSha1   = "HMAC-SHA1"
show_AssocType HmacSha256 = "HMAC-SHA256"


data SessionKeyType st
  = ServerKey   { getKey :: st }
  | ConsumerKey { getKey :: st }
  deriving Show


class SessionType st where
  fromParams :: Params -> Maybe (SessionKeyType st)
  getParams  :: st -> (String,[Word8])


-- | Turn a session type into a list of parameters
toParams :: SessionType st => SessionKeyType st -> Params
toParams skt = case skt of
  ServerKey   st -> params "openid.dh_server_key"   st
  ConsumerKey st -> params "openid.dh_consumer_key" st
  where
  params kty st =
    [ ("openid.session_type", ty)
    , (kty, encodeRaw True (btwoc key))
    ]
    where (ty,key) = getParams st


newtype DhSha1 = DhSha1 { dhSha1Key :: [Word8] } deriving Show

instance SessionType DhSha1 where
  fromParams ps = do
    let l k = lookup k ps
    ty <- l "openid.session_type"
    guard (ty == "DH-SHA1")
    (f,key) <- case l "openid.dh_consumer_public" of
      Just key -> return (ConsumerKey,key)
      Nothing -> do
        key <- l "openid.dh_server_public"
        return (ServerKey,key)
    return $ f $ DhSha1 $ decode key
  getParams (DhSha1 key) = ("DH-SHA1", key)


newtype DhSha256 = DhSha256 { dhSha256Key :: [Word8] } deriving Show

instance SessionType DhSha256 where
  fromParams ps = do
    let l k = lookup k ps
    ty <- l "openid.session_type"
    guard (ty == "DH-SHA256")
    (f,key) <- case l "openid.dh_consumer_public" of
      Just key -> return (ConsumerKey,key)
      Nothing -> do
        key <- l "openid.dh_server_public"
        return (ServerKey,key)
    return $ f $ DhSha256 $ decode key
  getParams (DhSha256 key) = ("DH-SHA256", key)


data NoEncryption = NoEncryption deriving Show

instance SessionType NoEncryption where
  fromParams ps = do
    ty <- lookup "openid.session_type" ps
    guard (ty == "no-encryption")
    case lookup "openid.mode" ps of
      Just {} -> return $ ConsumerKey NoEncryption
      Nothing -> return $ ServerKey   NoEncryption
  getParams NoEncryption = ("no-encryption", [])


data Association st = Association
  { assocHandle       :: String
  , assocType         :: AssocType
  , assocExpires      :: Int
  , assocMacKey       :: [Word8]
  , assocModulus      :: Maybe Integer
  , assocGenerator    :: Maybe Int
  , assocSessionType  :: SessionKeyType st
  } deriving Show


associationFromParams :: SessionType st
                      => Maybe [Word8] -> Params -> Result (Association st)
associationFromParams pubKey ps = do
  let l k = maybeToResult ("field not present: " ++ k) $ lookup k ps
      r k = maybeToResult ("unable to read: " ++ k) . readMaybe =<< l k
  ah  <- l "openid.assoc_handle"
  at  <- maybeToResult "unable to read: openid.assoc_type" . read_AssocType
         =<< l "openid.assoc_type"
  exp <- r "openid.expires_in"
  st  <- maybeToResult "unable to read session type" $ fromParams ps
  let dh h pk label = do
        mk <- decode `fmap` l label
        p <- r "openid.dh_modulus"
        g <- r "openid.dh_gen"
        k <- maybeToResult "no public key provided" pubKey
        let privKey = computeKey pk $ DHParams
                        { dhModulus    = p
                        , dhGenerator  = g
                        , dhPublicKey  = k
                        , dhPrivateKey = []
                        }
            hash = h privKey
            key = zipWith xor hash mk
        guard (length hash == length mk)
        return (key, Just p, Just g)
  (mk,mb_mod,mb_gen) <- case getParams (getKey st) of
    ("no-encryption", _) -> do mk <- l "openid.mac_key"
                               return (decode mk,Nothing,Nothing)
    ("DH-SHA1", k)       -> dh sha1   k "openid.enc_mac_key"
    ("DH-SHA256", k)     -> dh sha256 k "openid.enc_mac_key"
    (ty,_)               -> Error ("unsupported session type: " ++ ty)
  return Association { assocHandle      = ah
                     , assocType        = at
                     , assocExpires     = exp
                     , assocMacKey      = mk
                     , assocModulus     = mb_mod
                     , assocGenerator   = mb_gen
                     , assocSessionType = st
                     }


-- Signed Requests -------------------------------------------------------------

data Signed a = Signed
  { sigFields :: [String]
  , sigValue  :: [Word8]
  , sigParams :: Params
  } deriving Show


-- Authentication Requests -----------------------------------------------------

data AuthRequestMode = CheckIdSetup | CheckIdImmediate
  deriving Show

-- | Show a checkid mode.
show_AuthRequestMode :: AuthRequestMode -> String
show_AuthRequestMode CheckIdSetup     = "checkid_setup"
show_AuthRequestMode CheckIdImmediate = "checkid_immediate"


-- | Read a checkid mode
read_AuthRequestMode :: String -> Maybe AuthRequestMode
read_AuthRequestMode "checkid_setup"     = Just CheckIdSetup
read_AuthRequestMode "checkid_immediate" = Just CheckIdImmediate
read_AuthRequestMode _                   = Nothing


data AuthRequest = AuthRequest
  { authMode        :: AuthRequestMode
  , authNS          :: String
  , authClaimedId   :: Maybe Identifier
  , authIdentity    :: Maybe Identifier
  , authAssocHandle :: Maybe String
  , authReturnTo    :: Maybe String
  , authRealm       :: Maybe String
  } deriving Show


-- | Load an AuthRequest from a list of parameters.
paramsToAuthRequest :: Params -> Maybe AuthRequest
paramsToAuthRequest params = do
  am <- read_AuthRequestMode =<< lookup "openid.mode" params
  ns <- lookup "openid.ns" params
  let cid = lookup "openid.claimed_id"   params
      idt = lookup "openid.identity"     params
      rto = lookup "openid.return_to"    params
      ah  = lookup "openid.assoc_handle" params
      rlm = lookup "openid.realm"        params
  return $ AuthRequest { authMode        = am
                       , authNS          = ns
                       , authClaimedId   = Identifier `fmap` cid
                       , authIdentity    = Identifier `fmap` idt
                       , authAssocHandle = ah
                       , authReturnTo    = rto
                       , authRealm       = rlm
                       }
