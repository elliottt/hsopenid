
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
    show_CheckIdMode
  , read_CheckIdMode
  , authenticationURL
  ) where

-- Friends
import Network.OpenID.Association
import Network.OpenID.Types
import Network.OpenID.Utils

-- Libraries
import Data.List


-- | Show a checkid mode.
show_CheckIdMode :: CheckIdMode -> String
show_CheckIdMode Setup     = "checkid_setup"
show_CheckIdMode Immediate = "checkid_setup"


-- | Read a checkid mode
read_CheckIdMode :: String -> Maybe CheckIdMode
read_CheckIdMode "checkid_setup"     = Just Setup
read_CheckIdMode "checkid_immediate" = Just Immediate
read_CheckIdMode _                   = Nothing


-- | Request authentication
authenticationURL :: Maybe Association -> CheckIdMode
                  -> String -> Provider -> Identifier
                  -> String
authenticationURL mbassoc mode ret prov ident =
  let assoc = maybe [] assocToParams mbassoc
      idt   = getIdentifier ident
      params = concat
             $ intersperse "&"
             $ ("openid.mode=" ++ show_CheckIdMode mode)
             : ("openid.identity=" ++ escapeParam idt)
             : ("openid.claimed_id=" ++ escapeParam idt)
             : ("openid.ns=" ++ escapeParam "http://specs.openid.net/auth/2.0")
             : ("openid.return_to=" ++ escapeParam ret)
             : assoc
   in getProvider prov ++ '?':params
