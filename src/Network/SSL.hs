{-# LANGUAGE EmptyDataDecls, ForeignFunctionInterface #-}
{-# INCLUDE <openssl/err.h> #-}
{-# INCLUDE <openssl/rand.h> #-}
{-# INCLUDE <openssl/ssl.h> #-}

--------------------------------------------------------------------------------
-- |
-- Module      : Network.SSL
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : AllRightsReserved
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>
-- Stability   :
-- Portability :
--

module Network.SSL (
    -- * Types
    SSLHandle

    -- * Library Functions
  , sslInit
  , randSeed
  , sslConnect
  , sslRead
  , sslReadWhile
  , sslWrite
  ) where

-- Libraries
import Control.Monad
import Data.List
import Data.Maybe
import Data.Word
import Foreign.C
import Foreign.ForeignPtr
import Foreign.Marshal
import Foreign.Ptr
import Foreign.Storable
import Network.Socket
import Network.Stream


wrap m = Right `fmap` m `catch` handler
  where handler = return . Left . ErrorMisc . show


instance Stream SSLHandle where
  readLine sh = wrap (upd `fmap` sslReadWhile (/= c) sh)
    where
      c = toEnum (fromEnum '\n')
      upd bs = map (toEnum . fromEnum) bs ++ "\n"
  readBlock  sh n  = wrap (map (toEnum . fromEnum) `fmap` sslRead sh n)
  writeBlock sh bs = wrap $ sslWrite sh $ map (toEnum . fromEnum) bs
  close (SH (ssl,ctx,sock)) = do
    finalizeForeignPtr ssl
    finalizeForeignPtr ctx
    sClose sock




newtype SSLHandle = SH (ForeignPtr SSL,ForeignPtr SSL_CTX,Socket)

-- | Initialize OpenSSL
sslInit :: IO ()
sslInit  = do
  c_SSL_library_init
  c_SSL_load_error_strings


-- | Seed the PRNG.
--   On systems that don't provide /dev/urandom, use this to seed the PRNG.
randSeed :: [Word8] -> IO ()
randSeed bs = withArray bs (\buf -> c_RAND_seed buf len)
  where len = genericLength bs


-- | Initiate an ssl connection.
--   XXX: needs some error handling.
sslConnect :: Socket -> IO (Maybe SSLHandle)
sslConnect sock =
  notNull (c_SSL_CTX_new =<< c_SSLv23_client_method) $ \ctx  ->
  newForeignPtr p_SSL_CTX_free ctx                 >>= \pctx ->
  notNull (c_SSL_new ctx)                            $ \ssl  ->
  newForeignPtr p_SSL_shutdown ssl                 >>= \pssl ->
  setSocket ssl sock                               >>= \b    ->
  if not b
    then return Nothing
    else
      let loop = c_SSL_connect ssl >>= \ret -> case ret of
                   1 -> return $ Just $ SH (pssl,pctx,sock)
                   0 -> return Nothing
                   _ -> c_SSL_get_error ssl ret >>= \code -> case code of
                     2 -> loop
                     _ -> return Nothing
       in loop


-- | Read n bytes from an SSLHandle
sslRead :: SSLHandle -> Int -> IO [Word8]
sslRead (SH (pssl,_,_)) n = withForeignPtr pssl (loop n)
  where
    loop n ssl | n < 1024  = aux ssl n
               | otherwise = do xs <- aux ssl 1024
                                ys <- loop (n - 1024) ssl
                                return (xs ++ ys)
    aux ssl n = allocaArray n aux'
      where
        aux' buf = do
          ret <- c_SSL_read ssl buf (toEnum n)
          bs  <- peekArray (toEnum n) buf
          if ret >= 0
            then return bs
            else c_SSL_get_error ssl ret >>= \r -> case r of
                    -- need to try again to finish the read
                    2 -> aux' buf
                    0 -> return []
                    _ -> getError >>= error . ("sslRead: " ++)


sslReadWhile :: (Word8 -> Bool) -> SSLHandle -> IO [Word8]
sslReadWhile p (SH (pssl,_,_)) = withForeignPtr pssl f
  where
    f ssl = allocaArray 1 loop
      where
        loop buf = do
          ret <- c_SSL_read ssl buf 1
          b   <- peek buf
          if ret == 1 && p b
            then do
              bs <- loop buf
              return (b:bs)
            else c_SSL_get_error ssl ret >>= \r -> case r of
              2 -> loop buf
              0 -> return []
              _ -> getError >>= error . ("sslReadWhile: " ++)


-- | Write a block of bytes to an SSLHandle
sslWrite :: SSLHandle -> [Word8] -> IO ()
sslWrite _               [] = return ()
sslWrite (SH (pssl,_,_)) bs = withForeignPtr pssl $ \ssl -> withArrayLen bs (write ssl)
  where
    write ssl len buf = do
      ret <- c_SSL_write ssl buf (toEnum len)
      if ret > 0
        then return ()
        else c_SSL_get_error ssl ret >>= \r -> case r of
          2 -> write ssl len buf
          0 -> return ()
          _ -> getError >>= error . ("sslWrite:" ++)


-- Utility Functions -----------------------------------------------------------

notNull :: IO (Ptr a) -> (Ptr a -> IO (Maybe b)) -> IO (Maybe b)
notNull m f = do
  ptr <- m
  if ptr == nullPtr
    then return Nothing
    else f ptr


-- | Associate a socket with an SSL handle
setSocket :: Ptr SSL -> Socket -> IO Bool
setSocket ssl sock = c_SSL_set_fd ssl (fdSocket sock) >>= \ret ->
  case ret of
    1 -> return True
    _ -> return False


getError :: IO String
getError  = allocaArray 120 $ \array -> do
  c_ERR_error_string 120 array
  peekCString array


-- OpenSSL Interface -----------------------------------------------------------

data SSL_CTX
data SSL


foreign import ccall "openssl/ssl.h SSL_CTX_new"
  c_SSL_CTX_new :: Ptr () -> IO (Ptr SSL_CTX)

foreign import ccall "openssl/ssl.h SSLv23_client_method"
  c_SSLv23_client_method :: IO (Ptr ())

foreign import ccall "openssl/ssl.h SSL_library_init"
  c_SSL_library_init :: IO ()

foreign import ccall "openssl/ssl.h SSL_load_error_strings"
  c_SSL_load_error_strings :: IO ()

foreign import ccall "openssl/rand.h RAND_seed"
  c_RAND_seed :: Ptr Word8 -> CInt -> IO ()

foreign import ccall "openssl/ssl.h SSL_new"
  c_SSL_new :: Ptr SSL_CTX -> IO (Ptr SSL)

foreign import ccall "openssl/ssl.h &SSL_shutdown"
  p_SSL_shutdown :: FunPtr (Ptr SSL -> IO ())

foreign import ccall "openssl/ssl.h &SSL_CTX_free"
  p_SSL_CTX_free :: FunPtr (Ptr SSL_CTX -> IO ())

foreign import ccall "openssl/ssl.h SSL_set_fd"
  c_SSL_set_fd :: Ptr SSL -> CInt -> IO CInt

foreign import ccall "openssl/ssl.h SSL_connect"
  c_SSL_connect :: Ptr SSL -> IO CInt

foreign import ccall "openssl/ssl.h SSL_get_error"
  c_SSL_get_error :: Ptr SSL -> CInt -> IO CInt

foreign import ccall "openssl/err.h ERR_error_string"
  c_ERR_error_string :: CULong -> CString -> IO CString

foreign import ccall "openssl/ssl.h SSL_read"
  c_SSL_read :: Ptr SSL -> Ptr Word8 -> CInt -> IO CInt

foreign import ccall "openssl/ssl.h SSL_write"
  c_SSL_write :: Ptr SSL -> Ptr Word8 -> CInt -> IO CInt
