
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

module Network.OpenID.Types (
    AssocType(..)
  , SessionType(..)
  , Association(..)
  , Params
  , ReturnTo
  , Realm
  , Resolver
  , Provider
  , parseProvider
  , showProvider
  , providerURI
  , modifyProvider
  , Identifier(..)

    -- * Result Monad
  , Result(..)
  , result
  , resultToMaybe
  , maybeToResult
  , eitherToResult
  ) where

-- Libraries
import Control.Applicative
import Control.Monad
import Data.List
import Data.Word
import Network.URI

import qualified Network.HTTP as HTTP

--------------------------------------------------------------------------------
-- Types

-- | Supported association types
data AssocType = HmacSha1 | HmacSha256

instance Show AssocType where
  show HmacSha1   = "HMAC-SHA1"
  show HmacSha256 = "HMAC-SHA256"

instance Read AssocType where
  readsPrec _ str | "HMAC-SHA1"   `isPrefixOf` str = [(HmacSha1  ,drop  9  str)]
                  | "HMAC-SHA256" `isPrefixOf` str = [(HmacSha256, drop 11 str)]
                  | otherwise                      = []


-- | Session types for association establishment
data SessionType = NoEncryption | DhSha1 | DhSha256

instance Show SessionType where
  show NoEncryption = "no-encryption"
  show DhSha1       = "DH-SHA1"
  show DhSha256     = "DH-SHA256"

instance Read SessionType where
  readsPrec _ str
    | "no-encryption" `isPrefixOf` str = [(NoEncryption, drop 13 str)]
    | "DH-SHA1"       `isPrefixOf` str = [(DhSha1, drop 7 str)]
    | "DH-SHA256"     `isPrefixOf` str = [(DhSha256, drop 9 str)]
    | otherwise                        = []


-- | An association with a provider.
data Association = Association
  { assocExpiresIn :: Int
  , assocHandle    :: String
  , assocMacKey    :: [Word8]
  , assocType      :: AssocType
  } deriving Show

-- | Parameter lists for communication with the server
type Params = [(String,String)]

-- | A return to path
type ReturnTo = String

-- | A realm of uris for a provider to inform a user about
type Realm = String

-- | A way to resolve an HTTP request
type Resolver = (HTTP.Request -> IO (HTTP.Result HTTP.Response))

-- | An OpenID provider.
newtype Provider   = Provider { providerURI :: URI } deriving (Eq,Show)

-- | Parse a provider
parseProvider :: String -> Maybe Provider
parseProvider  = fmap Provider . parseURI

-- | Show a provider
showProvider :: Provider -> String
showProvider (Provider uri) = uriToString (const "") uri []

-- | Modify the URI in a provider
modifyProvider :: (URI -> URI) -> Provider -> Provider
modifyProvider f (Provider uri) = Provider (f uri)

-- | A valid OpenID identifier.
newtype Identifier = Identifier { getIdentifier :: String } deriving (Eq,Show)

-- | The result Monad
data Result a = Error String | Result a deriving Show

instance Functor Result where
  fmap f (Result x)  = Result (f x)
  fmap _ (Error err) = Error err

instance Applicative Result where
  pure = Result
  Result f  <*> Result x  = Result (f x)
  Result _  <*> Error err = Error err
  Error err <*> _         = Error err

instance Alternative Result where
  empty = Error "empty"
  r@(Result _) <|> _ = r
  _            <|> r = r

instance Monad Result where
  return = Result
  fail   = Error
  Result x   >>= f = f x
  Error  err >>= _ = Error err

instance MonadPlus Result where
  mzero = Error "mzero"
  mplus r@(Result _) _ = r
  mplus   (Error _)  r = r

-- | Case analysis for the Result type
result :: (String -> b) -> (a -> b) -> Result a -> b
result f _ (Error e)  = f e
result _ g (Result x) = g x

-- | Turn a Result into a Maybe
resultToMaybe :: Result a -> Maybe a
resultToMaybe  = result (const Nothing) Just

-- | Turn a Maybe into a Result
maybeToResult :: String -> Maybe a -> Result a
maybeToResult err mb = maybe (Error err) Result mb

-- | Turn an Either into a Result
eitherToResult :: Show a => Either a b -> Result b
eitherToResult  = either (Error . show) Result
