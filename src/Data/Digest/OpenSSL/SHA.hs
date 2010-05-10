{-# LANGUAGE ForeignFunctionInterface, EmptyDataDecls #-}

--------------------------------------------------------------------------------
-- |
-- Module      : Data.Digest.OpenSSL.SHA
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  :
-- Stability   :
-- Portability :
--

module Data.Digest.OpenSSL.SHA (sha1, sha256) where

import Control.Exception
import Foreign
import Foreign.C

data EVP_MD
data EVP_MD_CTX

-- | Sha1 hashing
{-# NOINLINE sha1 #-}
sha1 :: [Word8] -> [Word8]
sha1 = unsafePerformIO . hashWith c_EVP_sha1


-- | Sha256 hashing
{-# NOINLINE sha256 #-}
sha256 :: [Word8] -> [Word8]
sha256 = unsafePerformIO . hashWith c_EVP_sha256


-- | General purpose digest function wrapper for OpenSSL.
hashWith :: IO (Ptr EVP_MD) -> [Word8] -> IO [Word8]
hashWith hf bs =
  bracket c_EVP_MD_CTX_create c_EVP_MD_CTX_destroy $ \ evp_md_ctx ->
  withArrayLen (map (toEnum . fromEnum) bs) $ \ len arr -> do
    h <- hf
    c_EVP_DigestInit_ex  evp_md_ctx h nullPtr
    c_EVP_DigestUpdate   evp_md_ctx arr (toEnum len)
    allocaArray 64 $ \ hash ->
      alloca $ \ num  -> do
        c_EVP_DigestFinal_ex evp_md_ctx hash num
        n <- peek num
        hs <- peekArray (fromEnum n) hash
        return $ map (toEnum . fromEnum) hs




foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_create"
  c_EVP_MD_CTX_create :: IO (Ptr EVP_MD_CTX)

foreign import ccall unsafe "openssl/evp.h EVP_MD_CTX_destroy"
  c_EVP_MD_CTX_destroy :: Ptr EVP_MD_CTX -> IO ()

foreign import ccall unsafe "openssl/evp.h EVP_DigestInit_ex"
  c_EVP_DigestInit_ex :: Ptr EVP_MD_CTX -> Ptr EVP_MD -> Ptr () -> IO CInt

foreign import ccall unsafe "openssl/evp.h EVP_DigestUpdate"
  c_EVP_DigestUpdate :: Ptr EVP_MD_CTX -> Ptr CUChar -> CInt -> IO CInt

foreign import ccall unsafe "openssl/evp.h EVP_DigestFinal_ex"
  c_EVP_DigestFinal_ex :: Ptr EVP_MD_CTX -> Ptr CUChar -> Ptr CUInt -> IO CInt

foreign import ccall unsafe "openssl/evp.h EVP_sha1"
  c_EVP_sha1 :: IO (Ptr EVP_MD)

foreign import ccall unsafe "openssl/evp.h EVP_sha256"
  c_EVP_sha256 :: IO (Ptr EVP_MD)
