
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
import Control.Exception as E
import Network.Socket
import Network.Stream
import qualified Data.ByteString as B
import Control.Applicative
import Data.ByteString.Internal (w2c, c2w)
import Data.Word


data SSLHandle = SSLHandle SSLContext SSL

wrap m = Right `fmap` m `Prelude.catch` handler
  where
    handler err = return $ Left $ ErrorMisc $ "write: " ++ show err

wrapRead m = Right `fmap` m `catches` handlers
  where
    handlers :: [Handler (Either ConnError String)]
    handlers =
        [ Handler ((\_ -> return $ Right "")
          :: (ConnectionAbruptlyTerminated -> IO (Either ConnError String)))
        , Handler ((\x -> return $ Left $ ErrorMisc  $ "read: " ++ show x)
          :: (SomeException -> IO (Either ConnError String)))
        ]

-- The problem is that the OpenSSL library doesn't know that in some
-- cases, the HTTP server will rudely close its side of the write
-- socket once a complete HTTP response has been transmitted. In fact,
-- the server will also terminate its read end once we've sent a
-- complete header, but the HTTP driver doesn't seem to mind about
-- that bit. All this seems to be standard practice (regardless of
-- whether it is considered correct by SSL or not), so we should just
-- treat it as an EOF.
-- 
-- In the meantime, the Network.HTTP driver will stop reading on an
-- empty input (NOT an empty line terminated by a "\n"), so we should
-- return that.

instance Stream SSLHandle where
  readLine sh =
    wrapRead (upd `fmap` sslReadWhile (/= c) sh)
    where
      c      = toEnum (fromEnum '\n')
      upd bs = map (toEnum . fromEnum) bs ++ "\n"

  readBlock (SSLHandle _ ssl) n =
    wrapRead ((map w2c . B.unpack) <$> Session.read ssl n)

  writeBlock (SSLHandle _ ssl) bs =
    | not (null bs) = wrap   $ Session.write ssl $ B.pack $ map c2w $ bs
    | otherwise     = return $ Right ()

  -- should this really ignore all exceptions?
  close (SSLHandle _ ssl) = Session.shutdown ssl Bidirectional
    `E.catch` ((\_ -> return ()) :: SomeException -> IO ())

  closeOnEnd _ _ = return ()

sslConnect :: Socket -> IO (Maybe SSLHandle)
sslConnect sock = body `E.catch` handler
  where
  body = do
    ctx <- Session.context
    ssl <- Session.connection ctx sock
    Session.connect ssl
    return $ Just $ SSLHandle ctx ssl

  handler :: SomeException -> IO (Maybe SSLHandle)
  handler _ = return Nothing

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

