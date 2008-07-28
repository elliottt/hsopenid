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
import Network.OpenID.Utils

-- Libraries
import Control.Monad
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

instance Monad Result where
  return         = Result
  Error  e >>= _ = Error e
  Result a >>= f = f a
  fail           = Error

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


data SessionType
  = DhSha1   { stModulus :: Integer, stGenerator :: Int, stPublicKey :: [Word8] }
  | DhSha256 { stModulus :: Integer, stGenerator :: Int, stPublicKey :: [Word8] }
  deriving Show


-- | Read a session type from a set of parameters.  The Nothing case indicates
-- that no encryption was requested.
params_to_SessionType :: [Word8] -> Params -> Maybe SessionType
params_to_SessionType pkey ps = do
  let l k = lookup k ps
  ty <- l "openid.session_type"
  guard (ty /= "no-encryption")
  let dec = roll . decode
  m   <- dec `fmap` l "openid.dh_modulus"
  gen <- dec `fmap` l "openid.dh_gen"
  f <- case ty of
    "DH-SHA1"   -> return DhSha1
    "DH-SHA256" -> return DhSha256
    _           -> Nothing
  return $ f m (fromInteger gen) pkey


-- | Show a session type.
sessionType_to_params :: SessionType -> Params
sessionType_to_params st = case st of
  DhSha1   m g pk -> f m g pk "DH-SHA1"
  DhSha256 m g pk -> f m g pk "DH-SHA256"
  where
  enc = encodeRaw True . btwoc
  f m g pk t = [ ("openid.session_type", t)
               , ("openid.dh_modulus", enc $ unroll m)
               , ("openid.dh_gen", enc $ unroll $ toEnum g)
               , ("openid.dh_consumer_public", enc pk)
               ]


data Association = Association
  { assocHandle  :: String
  , assocType    :: AssocType
  , assocExpires :: Int
  , assocMacKey  :: String
  } deriving Show


data AssocRequest = AssocRequest
  { arNS               :: String
  , arType             :: AssocType
  , arSessionType      :: SessionType
  } deriving Show


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
