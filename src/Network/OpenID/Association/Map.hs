
--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Assocation.Map
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>
-- Stability   :
-- Portability :
--

module Network.OpenID.Association.Map (
    -- Association Map
    AssociationMap(..)
  , emptyAssociationMap
  ) where

-- friends
import Network.OpenID.Association.Manager
import Network.OpenID.Types

-- libraries
import Data.Time
import qualified Data.Map as Map


-- | A simple association manager based on Data.Map
newtype AssociationMap = AM (Map.Map String (UTCTime,Association))
    deriving (Show,Read)

instance AssociationManager AssociationMap where
  findAssociation (AM m) p = snd `fmap` Map.lookup (showProvider p) m

  addAssociation (AM m) now p a = AM (Map.insert (showProvider p) (expire,a) m)
    where expire = addUTCTime (toEnum (assocExpiresIn a)) now

  expire (AM m) now = AM (Map.filter ((now >) . fst) m)

  exportAssociations (AM m) = map f (Map.toList m)
    where f (p,(t,a)) = (p,t,a)


-- | An empty association map.
emptyAssociationMap :: AssociationMap
emptyAssociationMap  = AM Map.empty
