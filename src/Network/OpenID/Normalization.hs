
--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Normalization
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>
-- Stability   : 
-- Portability : 
--

module Network.OpenID.Normalization where

-- Friends
import Network.OpenID.Types

-- Libraries
import Control.Applicative
import Control.Monad
import Data.List
import Network.URI hiding (scheme,path)


-- | Normalize an identifier, discarding XRIs.
normalizeIdentifier :: Identifier -> Maybe Identifier
normalizeIdentifier  = normalizeIdentifier' (const Nothing)


-- | Normalize the user supplied identifier, using a supplied function to
-- normalize an XRI.
normalizeIdentifier' :: (String -> Maybe String) -> Identifier
                     -> Maybe Identifier
normalizeIdentifier' xri (Identifier str)
  | null str                  = Nothing
  | "xri://" `isPrefixOf` str = Identifier `fmap` xri str
  | head str `elem` "=@+$!"   = Identifier `fmap` xri str
  | otherwise = fmt `fmap` (url >>= norm)
  where
    url = parseURI str <|> parseURI ("http://" ++ str)

    norm uri = validScheme >> return u
      where
        scheme      = uriScheme uri
        validScheme = guard (scheme == "http:" || scheme == "https:")
        u = uri { uriFragment = "", uriPath = path }
        path | null (uriPath uri) = "/"
             | otherwise          = uriPath uri

    fmt u = Identifier
          $ normalizePathSegments
          $ normalizeEscape
          $ normalizeCase
          $ uriToString (const "") u []
