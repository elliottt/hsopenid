
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
    -- * Types
    CheckIdMode(..)

    -- * Authentication
  , authenticationURI
  ) where

-- Friends
import Network.OpenID.AssociationManager
import Network.OpenID.Types
import Network.OpenID.Utils

-- Libraries
import Data.List
import Network.URI


--------------------------------------------------------------------------------
-- Types

data CheckIdMode = Immediate | Setup

instance Show CheckIdMode where
  show Immediate = "checkid_immediate"
  show Setup     = "checkid_setup"

instance Read CheckIdMode where
  readsPrec _ s | "checkid_immediate" `isPrefixOf` s = [(Immediate, drop 17 s)]
                | "checkid_setup"     `isPrefixOf` s = [(Setup, drop 13 s)]
                | otherwise                          = []

--------------------------------------------------------------------------------
-- Authentication

-- | Generate an authentication URL
authenticationURI :: AssociationManager am
                  => am -> CheckIdMode -> Provider -> Identifier -> ReturnTo
                  -> Maybe Realm -> URI
authenticationURI am mode prov ident rt mb_realm =
  addParams params (providerURI prov)
  where
    params = [ ("openid.ns", openidNS)
             , ("openid.mode", show mode)
             , ("openid.claimed_id", getIdentifier ident)
             , ("openid.identity", getIdentifier ident)
             , ("openid.return_to", rt)
             ] ++ ah ++
             maybe [] (\r -> [("openid.realm", r)]) mb_realm
    ah = case findAssociation am prov of
      Nothing -> []
      Just a  -> [("openid.assoc_handle", assocHandle a)]
