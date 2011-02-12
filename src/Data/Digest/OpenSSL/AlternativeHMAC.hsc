{-# LANGUAGE ForeignFunctionInterface, EmptyDataDecls #-}

module Data.Digest.OpenSSL.AlternativeHMAC
    ( hmac
    , showHMAC
    , sha
    , sha1
    , sha224
    , sha256
    , sha384
    , sha512
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Numeric (showHex)
import System.IO.Unsafe

import OpenSSL.EVP.Digest

#include <openssl/objects.h>
#include <openssl/evp.h>

-- Types -----------------------------------------------------------------------

-- | Name of the SHA digest, used by getDigestByName
sha :: String
sha = #const_str SN_sha

-- | Name of the SHA1 digest, used by getDigestByName
sha1 :: String
sha1 = #const_str SN_sha1

-- | Name of the SHA224 digest, used by getDigestByName
sha224 :: String
sha224 = #const_str SN_sha224

-- | Name of the SHA256 digest, used by getDigestByName
sha256 :: String
sha256 = #const_str SN_sha256

-- | Name of the SHA384 digest, used by getDigestByName
sha384 :: String
sha384 = #const_str SN_sha384

-- | Name of the SHA384 digest, used by getDigestByName
sha512 :: String
sha512 = #const_str SN_sha512



-- | Get the hex-string representation of an HMAC
showHMAC :: ByteString -- ^ the HMAC
         -> String     -- ^ the hex-string representation
showHMAC bs =
    concatMap draw $ BS.unpack bs
    where
      draw :: (Integral a) => a -> String
      draw w = case showHex w [] of
                 [x] -> ['0', x]
                 x   -> x

-- | Wrapper/rendering function for hmac
hmac :: String      -- ^ the name of the digest
     -> ByteString  -- ^ the HMAC key
     -> ByteString  -- ^ the data to be signed
     -> String      -- ^ the hex-representation of the resulting HMAC
hmac s k i = 
  unsafePerformIO $
  getDigestByName s >>= \mbDigest ->
  case mbDigest of
    Nothing -> fail "no digest"
    Just d ->
        return $ showHMAC $ hmacBS d k i
