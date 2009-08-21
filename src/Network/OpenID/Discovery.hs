{-# LANGUAGE FlexibleContexts #-}

--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Discovery
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>
-- Stability   :
-- Portability :
--

module Network.OpenID.Discovery (
    -- * Discovery
    discover
  ) where

-- Friends
import Network.OpenID.Types
import Text.XRDS

-- Libraries
import Data.Char
import Data.List
import Data.Maybe
import MonadLib
import Network.HTTP
import Network.URI


type M = ExceptionT Error


-- | Attempt to resolve an OpenID endpoint, and user identifier.
discover :: Monad m
         => Resolver m -> Identifier -> m (Either Error (Provider,Identifier))
discover resolve ident = do
  res <- runExceptionT (discoverYADIS resolve ident Nothing)
  case res of
    Right {} -> return res
    _        -> runExceptionT (discoverHTML resolve ident)


-- YADIS-Based Discovery -------------------------------------------------------

-- | Attempt a YADIS based discovery, given a valid identifier.  The result is
--   an OpenID endpoint, and the actual identifier for the user.
discoverYADIS :: Monad m
              => Resolver m -> Identifier -> Maybe String
              -> M m (Provider,Identifier)
discoverYADIS resolve ident mb_loc = do
  let err = raise . Error
      uri = fromMaybe (getIdentifier ident) mb_loc
  case parseURI uri of
    Nothing  -> err "Unable to parse identifier as a URI"
    Just uri -> do
      estr <- lift $ resolve Request
        { rqMethod  = GET
        , rqURI     = uri
        , rqHeaders = []
        , rqBody    = ""
        }
      case estr of
        Left  e   -> err $ "HTTP request error: " ++ show e
        Right rsp -> case rspCode rsp of
          (2,0,0) -> case findHeader (HdrCustom "X-XRDS-Location") rsp of
            Just loc -> discoverYADIS resolve ident (Just loc)
            _        -> do
              let e = err "Unable to parse YADIS document"
              doc <- maybe e return $ parseXRDS $ rspBody rsp
              parseYADIS ident doc
          _       -> err $ "HTTP request error: unexpected response code "++show (rspCode rsp)


-- | Parse out an OpenID endpoint, and actual identifier from a YADIS xml
-- document.
parseYADIS :: ExceptionM m Error
           => Identifier -> XRDS -> m (Provider,Identifier)
parseYADIS ident = handleError . listToMaybe . mapMaybe isOpenId . concat
  where
  handleError = maybe e return
    where e = raise (Error "YADIS document doesn't include an OpenID provider")
  isOpenId svc = do
    let tys = serviceTypes svc
        localId = maybe ident Identifier $ listToMaybe $ serviceLocalIDs svc
        f (x,y) | x `elem` tys = Just y
                | otherwise    = mzero
    lid <- listToMaybe $ mapMaybe f
      [ ("http://specs.openid.net/auth/2.0/server", ident)
      -- claimed identifiers
      , ("http://specs.openid.net/auth/2.0/signon", localId)
      , ("http://openid.net/signon/1.0"           , localId)
      , ("http://openid.net/signon/1.1"           , localId)
      ]
    uri <- parseProvider =<< listToMaybe (serviceURIs svc)
    return (uri,lid)


-- HTML-Based Discovery --------------------------------------------------------

-- | Attempt to discover an OpenID endpoint, from an HTML document.  The result
-- will be an endpoint on success, and the actual identifier of the user.
discoverHTML :: Monad m
             => Resolver m -> Identifier -> M m (Provider,Identifier)
discoverHTML resolve ident = do
  let err = raise . Error
  case parseURI (getIdentifier ident) of
    Nothing  -> err "Unable to parse identifier as a URI"
    Just uri -> do
      estr <- lift $ resolve Request
        { rqMethod  = GET
        , rqURI     = uri
        , rqHeaders = []
        , rqBody    = ""
        }
      case estr of
        Left  e   -> err $ "HTTP request error: " ++ show e
        Right rsp -> case rspCode rsp of
          (2,0,0) -> maybe (err "Unable to find identifier in HTML") return
                       $ parseHTML ident $ rspBody rsp
          _       -> err $ "HTTP request error: unexpected response code "++show (rspCode rsp)


-- | Parse out an OpenID endpoint and an actual identifier from an HTML
-- document.
parseHTML :: Identifier -> String -> Maybe (Provider,Identifier)
parseHTML ident = resolve
                . filter isOpenId
                . linkTags
                . htmlTags
  where
    isOpenId (rel,_) = "openid" `isPrefixOf` rel
    resolve ls = do
      prov <- parseProvider =<< lookup "openid2.provider" ls
      let lid = maybe ident Identifier $ lookup "openid2.local_id" ls
      return (prov,lid)


-- | Filter out link tags from a list of html tags.
linkTags :: [String] -> [(String,String)]
linkTags  = mapMaybe f . filter p
  where
    p = ("link " `isPrefixOf`)
    f xs = do
      let ys = unfoldr splitAttr (drop 5 xs)
      x <- lookup "rel"  ys
      y <- lookup "href" ys
      return (x,y)


-- | Split a string into strings of html tags.
htmlTags :: String -> [String]
htmlTags [] = []
htmlTags xs = case break (== '<') xs of
  (as,_:bs) -> fmt as : htmlTags bs
  (as,[])   -> [as]
  where
    fmt as = case break (== '>') as of
      (bs,_) -> bs


-- | Split out values from a key="value" like string, in a way that
-- is suitable for use with unfoldr.
splitAttr :: String -> Maybe ((String,String),String)
splitAttr xs = case break (== '=') xs of
  (_,[])         -> Nothing
  (key,_:'"':ys) -> f key (== '"') ys
  (key,_:ys)     -> f key isSpace  ys
  where
  f key p cs = case break p cs of
      (_,[])         -> Nothing
      (value,_:rest) -> Just ((key,value), dropWhile isSpace rest)
