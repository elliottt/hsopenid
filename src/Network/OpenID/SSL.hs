
--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.HTTP
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>
-- Stability   :
-- Portability :
--

module Network.OpenID.SSL (
        SSLHandle,
        sslConnect
    ) where

import OpenSSL.Session as Session
import Network.Socket
import Network.Stream
import qualified Data.ByteString as B
import Control.Applicative
import Data.ByteString.Internal (w2c, c2w)
import Data.Word


data SSLHandle = SSLHandle SSLContext SSL

wrap m = Right `fmap` m `catch` handler
  where handler = return . Left . ErrorMisc . show

instance Stream SSLHandle where
  readLine sh = wrap (upd `fmap` sslReadWhile (/= c) sh)
    where
      c = toEnum (fromEnum '\n')
      upd bs = map (toEnum . fromEnum) bs ++ "\n"
  readBlock  (SSLHandle _ ssl) n  = wrap $ (map w2c . B.unpack) <$> Session.read ssl n
  writeBlock (SSLHandle _ ssl) bs = wrap $ Session.write ssl $ B.pack $ map c2w $ bs
  close (SSLHandle _ ssl) = Session.shutdown ssl Bidirectional `catch` \_ -> return ()

sslConnect :: Socket -> IO (Maybe SSLHandle)
sslConnect sock = do
  catch (do
      ctx <- Session.context
      ssl <- Session.connection ctx sock
      Session.connect ssl
      return $ Just $ SSLHandle ctx ssl
    )
    (\_ -> return Nothing)

sslReadWhile :: (Word8 -> Bool) -> SSLHandle -> IO [Word8]
sslReadWhile pred (SSLHandle _ ssl) = rw
  where
    rw = do
      txt <- Session.read ssl 1
      if B.null txt
        then return []
        else do
          let c = B.head txt
          if pred c
            then do
                cs <- rw
                return (c:cs)
            else
                return []

