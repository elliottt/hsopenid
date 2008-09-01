
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

module Network.OpenID.HTTP (
    makeRequest
  ) where

-- friends
import Network.OpenID.Types
import Network.OpenID.Utils
import Network.SSL

-- libraries
import MonadLib
import Network.BSD
import Network.HTTP
import Network.Socket
import Network.URI


-- | Perform an http request
makeRequest :: Resolver
makeRequest req = case getAuthority (rqURI req) of
  Left err -> return (Left err)
  Right (host,port) -> do
    hi   <- getHostByName host
    sock <- socket AF_INET Stream 0
    connect sock $ SockAddrInet port $ head $ hostAddresses hi
    if uriScheme (rqURI req) == "https:"
      then inBase $ do
        mb_sh <- inBase (sslConnect sock)
        case mb_sh of
          Nothing -> return $ Left $ ErrorMisc "sslConnect failed"
          Just sh -> simpleHTTP_ sh req
      else simpleHTTP_ sock req


-- | Get the port and hostname associated with an http request
getAuthority :: URI -> Either ConnError (HostName,PortNumber)
getAuthority uri = case uriAuthority uri of
  Nothing   -> Left $ ErrorMisc "No uri authority"
  Just auth ->
    let host = uriRegName auth
        readPort = readMaybe . tail
        port | null (uriPort auth) = case uriScheme uri of
                "https:" -> Just 443
                "http:"  -> Just 80
                _        -> Nothing
             | otherwise = fromInteger `fmap` readPort (uriPort auth)
     in case port of
          Nothing -> Left $ ErrorMisc "Unable to parse port number"
          Just p  -> Right (host,p)
