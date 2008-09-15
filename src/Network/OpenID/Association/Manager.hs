
--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Network.Class
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : AllRightsReserved
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>
-- Stability   :
-- Portability :
--

module Network.OpenID.Association.Manager where

-- friends
import Network.OpenID.Types

-- libraries
import Data.Time


-- | Manage pairs of Providers and Associations.
class AssociationManager am where
  -- | Find an association.
  findAssociation :: am -> Provider -> Maybe Association

  -- | Add a new association, and set its expiration to be relative to the "now"
  --   parameter passed in.
  addAssociation :: am -> UTCTime -> Provider -> Association -> am

  -- | Expire associations in the manager that are older than the supplied "now"
  --   parameter.
  expire :: am -> UTCTime -> am

  -- | Export all associations, and their expirations
  exportAssociations :: am -> [(String,UTCTime,Association)]
