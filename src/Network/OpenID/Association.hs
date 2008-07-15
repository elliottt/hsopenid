
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
    read_AssocType, show_AssocType
  , assocToParams
  , getHashFunction

    -- * Association
  , associate
  , verifySignature
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

-- | Read an association type out of a string.
read_AssocType :: String -> Maybe AssocType
read_AssocType "HMAC-SHA1"   = Just HmacSha1
read_AssocType "HMAC-SHA256" = Just HmacSha256
read_AssocType _             = Nothing


-- | Show an association type.
show_AssocType :: AssocType -> String
show_AssocType HmacSha1   = "HMAC-SHA1"
show_AssocType HmacSha256 = "HMAC-SHA256"


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

-- | Attempt to associate to a provider.
associate :: Monad m
          => Request m -> Maybe AssocType -> Provider -> m (Maybe Association)
associate resolve mbty ep = do
  let ty   = show_AssocType $ fromMaybe HmacSha1 mbty
      body = concat $ intersperse "&"
        [ "openid.mode=associate"
        , "openid.assoc_type=" ++ ty
        ]
  eresp <- resolve (getProvider ep) body
  case eresp of
    Left  {}      -> return Nothing
    Right (_,str) ->
      let split xs = case break (== ':') xs of
            (as,_:bs) -> (as,bs)
            (as,[])   -> (as,[])
          resp = map split $ lines str
       in case lookup "error" resp of
          Just {} -> return Nothing
          Nothing -> return $ do
            let l k = lookup k resp
            h <-                    l "assoc_handle"
            t <- read_AssocType =<< l "assoc_type"
            e <- readMaybe      =<< l "expires_in"
            m <-                    l "mac_key"
            return $ Association h t e m


-- Verification ----------------------------------------------------------------

-- | Verify a signature provided in a response.
verifySignature :: Association -> String -> Bool
verifySignature assoc uri = fromMaybe False $ do
  let params = parseParams uri
      l k = k `lookup` params
  sig64 <- l "openid.sig"
  fields <- parseSignedFields `fmap` l "openid.signed"
  let sig = decode sig64
      p (k,_) = k `elem` fields
      sparams = filter p params
      f = getHashFunction (assocType assoc)
      key = B.pack $ decode (assocMacKey assoc)
      msg = generateMessage sparams
  case readHex (unsafeHMAC f key msg) of
    [(x,"")] -> Just (unroll x == sig)
    _        -> Nothing


generateMessage :: [(String,String)] -> B.ByteString
generateMessage  = B.pack . map (toEnum . fromEnum) . concatMap f
  where
    f (key,value) | "openid." `isPrefixOf` key = fmt (drop 7 key) value
                  | otherwise                  = fmt key value
    fmt k v = k ++ ":" ++ v ++ "\n"


parseSignedFields :: String -> [String]
parseSignedFields  = map ("openid." ++) . breaks (== ',')


parseParams :: String -> [(String,String)]
parseParams xs = case break (== '?') xs of
  (_,_:bs) -> map f (breaks (== '&') bs)
  _        -> []
  where
  f ys = case break (== '=') ys of
    (as,_:bs) -> (as, unEscapeString bs)
    (as,[])   -> (as, [])
