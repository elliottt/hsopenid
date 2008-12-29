
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
    -- * Request Interface
    makeRequest

    -- * HTTP Utilities
  , getRequest
  , postRequest

    -- * Request/Response Parsing and Formatting
  , parseDirectResponse
  , formatParams
  , formatDirectParams
  , escapeParam
  , addParams
  , parseParams
  ) where

-- friends
import Network.OpenID.Types
import Network.OpenID.Utils
import Network.SSL

-- libraries
import Data.List
import MonadLib
import Network.BSD
import Network.HTTP hiding (host,port)
import Network.Socket
import Network.URI hiding (query)


-- | Perform an http request.
--   If the Bool parameter is set to True, redirects from the server will be
--   followed.
makeRequest :: Bool -> Resolver IO
makeRequest followRedirect req = case getAuthority (rqURI req) of
  Left err -> return (Left err)
  Right (host,port) -> do
    hi   <- getHostByName host
    sock <- socket AF_INET Stream 0
    connect sock $ SockAddrInet port $ head $ hostAddresses hi
    ersp <- if uriScheme (rqURI req) == "https:"
              then inBase $ do
                mb_sh <- inBase (sslConnect sock)
                case mb_sh of
                  Nothing -> return $ Left $ ErrorMisc "sslConnect failed"
                  Just sh -> simpleHTTP_ sh req
              else simpleHTTP_ sock req
    case ersp of
      Left  err -> return (Left err)
      Right rsp -> handleRedirect followRedirect req rsp


-- | Follow a redirect
handleRedirect :: Bool -> Request -> Response -> IO (Either ConnError Response)
handleRedirect False _   rsp = return (Right rsp)
handleRedirect _     req rsp = case rspCode rsp of
  (3,0,2) -> case parseURI =<< findHeader HdrLocation rsp of
    Just uri -> makeRequest False req { rqURI = uri }
    Nothing  -> return (Right rsp)
  _       -> return (Right rsp)


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

-- Utilities -------------------------------------------------------------------


getRequest :: URI -> Request
getRequest uri = Request
  { rqURI     = uri
  , rqMethod  = GET
  , rqHeaders = []
  , rqBody    = ""
  }


postRequest :: URI -> String -> Request
postRequest uri body = Request
  { rqURI     = uri
  , rqMethod  = POST
  , rqHeaders =
    [ Header HdrContentType "application/x-www-form-urlencoded"
    , Header HdrContentLength $ show $ length body
    ]
  , rqBody    = body
  }

-- Parsing and Formatting ------------------------------------------------------

-- | Turn a response body into a list of parameters.
parseDirectResponse :: String -> Params
parseDirectResponse  = unfoldr step
  where
    step []  = Nothing
    step str = case split (== '\n') str of
      (ps,rest) -> Just (split (== ':') ps,rest)


-- | Format OpenID parameters as a query string
formatParams :: Params -> String
formatParams  = intercalate "&" . map f
  where f (x,y) = x ++ "=" ++ escapeParam y


-- | Format OpenID parameters as a direct response
formatDirectParams :: Params -> String
formatDirectParams  = concatMap f
  where f (x,y) = x ++ ":" ++ y ++ "\n"


-- | Escape for the query string of a URI
escapeParam :: String -> String
escapeParam  = escapeURIString isUnreserved


-- | Add Parameters to a URI
addParams :: Params -> URI -> URI
addParams ps uri = uri { uriQuery = query }
  where
    f (k,v) = (k,v)
    ps' = map f ps
    query = '?' : formatParams (parseParams (uriQuery uri) ++ ps')


-- | Parse OpenID parameters out of a url string
parseParams :: String -> Params
parseParams xs = case split (== '?') xs of
  (_,bs) -> unfoldr step bs
  where
    step [] = Nothing
    step bs = case split (== '&') bs of
      (as,rest) -> case split (== '=') as of
        (k,v) -> Just ((k, unEscapeString v),rest)
