{-# LANGUAGE EmptyDataDecls #-}

--------------------------------------------------------------------------------
-- |
-- Module      : Network.OpenID.Types
-- Copyright   : (c) Trevor Elliott, 2008
-- License     : BSD3
--
-- Maintainer  : Trevor Elliott <trevor@geekgateway.com>Association.hs
-- Stability   : 
-- Portability : 
--

module Network.OpenID.Types where

-- Libraries
import Network.HTTP


data YADIS
data HTML


type Resolver m t = String -> m (Either String ([Header],String))


type Request m = String -> String -> m (Either String ([Header],String))


newtype Provider   = Provider   { getProvider   :: String } deriving (Eq,Show)
newtype Identifier = Identifier { getIdentifier :: String } deriving (Eq,Show)


data Association = Association
  { assocHandle  :: String
  , assocType    :: AssocType
  , assocExpires :: Int
  , assocMacKey  :: String
  } deriving Show


data AssocType = HmacSha1 | HmacSha256
  deriving Show


data CheckIdMode = Setup | Immediate deriving Show
