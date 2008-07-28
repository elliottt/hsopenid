
--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Authentication
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>
-- Stability   :
-- Portability :
--

module Network.OpenID.Authentication (
    authenticationURL
  ) where

-- Friends
import Network.OpenID.Association
import Network.OpenID.Types
import Network.OpenID.Utils

-- Libraries
import Data.List


-- | Request authentication
authenticationURL :: Maybe Association -> AuthRequestMode
                  -> String -> Provider -> Identifier
                  -> String
authenticationURL mbassoc mode ret prov ident =
  let assoc = maybe [] assocToParams mbassoc
      idt   = getIdentifier ident
      params = concat
             $ intersperse "&"
             $ ("openid.mode=" ++ show_AuthRequestMode mode)
             : ("openid.identity=" ++ escapeParam idt)
             : ("openid.claimed_id=" ++ escapeParam idt)
             : ("openid.ns=" ++ escapeParam "http://specs.openid.net/auth/2.0")
             : ("openid.return_to=" ++ escapeParam ret)
             : assoc
   in getProvider prov ++ '?':params
