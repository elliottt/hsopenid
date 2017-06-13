module Network.OpenID.AttributeExchange (
    AXFieldTy(..),
    AXFieldVal,
    axName, axSpec, axTyFromName,

    axEmailRequired,
    axExtParams,
    axExtParams',
    getAxFields
) where

import Prelude()
import Prelude.Compat
import Control.Monad (guard)
import Network.OpenID.Types

import Data.Maybe (listToMaybe, mapMaybe, fromMaybe)
import Data.List (intercalate, nub, isPrefixOf)

defaultAlias :: String
defaultAlias = "ax"

extNamespace, extNamespacePrefix, extMode_fetchRequest :: String
extNamespace  = "http://openid.net/srv/ax/1.0"
extNamespacePrefix = "http://openid.net/srv/ax/1." 
extMode_fetchRequest = "fetch_request"

-- | Some common, useful Attribute Exchange specs.
data AXFieldTy
    = AXBirthdate
    | AXEmail
    | AXFirstName
    | AXFullName
    | AXGender
    | AXLanguage
    | AXLastName
    | AXNickname
      deriving (Eq, Show, Ord, Read)


axName :: AXFieldTy -> String
axName AXBirthdate = "birthdate"
axName AXEmail     = "email"
axName AXFirstName = "firstname"
axName AXFullName  = "fullname"
axName AXGender    = "gender"
axName AXLanguage  = "language"
axName AXLastName  = "lastname"
axName AXNickname  = "friendly"

axSpec :: AXFieldTy -> String
axSpec AXBirthdate = "http://axschema.org/birthDate"
axSpec AXEmail     = "http://axschema.org/contact/email"
axSpec AXFirstName = "http://axschema.org/namePerson/first"
axSpec AXFullName  = "http://axschema.org/namePerson"
axSpec AXGender    = "http://axschema.org/person/gender"
axSpec AXLanguage  = "http://axschema.org/pref/language"
axSpec AXLastName  = "http://axschema.org/namePerson/last"
axSpec AXNickname  = "http://axschema.org/namePerson/friendly"

axTyFromName :: String -> Maybe AXFieldTy
axTyFromName "birthdate" = Just AXBirthdate
axTyFromName "email"     = Just AXEmail
axTyFromName "firstname" = Just AXFirstName
axTyFromName "fullname"  = Just AXFullName
axTyFromName "gender"    = Just AXGender
axTyFromName "language"  = Just AXLanguage
axTyFromName "lastname"  = Just AXLastName
axTyFromName "friendly"  = Just AXNickname
axTyFromName _           = Nothing


-- | Used to store responses.
type AXFieldVal = (AXFieldTy, String)


-- | The simplest use case is to request the user's email. This would be
--   used to replace traditional verification emails.
axEmailRequired :: Params
axEmailRequired = axExtParams [AXEmail]


-- | Use these functions to roll your own list of fields to request when
--   you send an auth request
axExtParams :: [AXFieldTy]    -- ^ params we want them to send in the
                              -- "id_res" mode verification
            -> Params
axExtParams =  axExtParams' defaultAlias


-- | specify the alias as well as the list of requested fields
axExtParams' :: String        -- ^ alias. it doesn't really matter
                              -- what this is as long as we're
                              -- consistent
             -> [AXFieldTy]   -- ^ params we require in the "id_res"
                              -- mode verification
             -> Params
axExtParams' alias extsRequired =
    [ ("openid.ns." ++ alias, extNamespace)
    , ("openid." ++ alias ++ ".mode", extMode_fetchRequest)
    , ("openid." ++ alias ++ ".required", formatRequiredVal extsRequired')
    ] ++ exts
    where
      exts = map (formatRequestField alias) extsRequired'
      extsRequired' = nub extsRequired


formatRequestField :: String -> AXFieldTy -> (String, String)
formatRequestField alias field =
    ("openid." ++ alias ++ ".type." ++ axName field, axSpec field)


formatRequiredVal :: [AXFieldTy] -> String
formatRequiredVal =
    intercalate "," . map axName


-- | Retrieve the requested fields from the HTTP request params. Keep
-- | in mind the spec does not require that the OpenID Provider return
-- | any of our requested fields, even on a successful verification.
getAxFields :: Params -> [AXFieldVal]
getAxFields ps =
    fromMaybe [] fieldsMb
    where
      fieldsMb :: Maybe [AXFieldVal]
      fieldsMb = getAxFields' ps <$> aliasMb

      aliasMb :: Maybe String
      aliasMb = listToMaybe $ mapMaybe getAxAlias ps


getAxFields' :: Params -> String -> [AXFieldVal]
getAxFields' ps alias =
    mapMaybe getAxFieldTypes' ps
    where
      getAxFieldTypes' :: (String, String) -> Maybe AXFieldVal
      getAxFieldTypes' (n,v) = do
        guard (valueAliasPrefix `isPrefixOf` n)
        ty <- axTyFromName $ drop (length valueAliasPrefix) n
        return (ty,v)

      valueAliasPrefix = "openid." ++ alias ++ ".value."


-- the server will return a response of the form
--   openid.ALIAS.value.email: "foobar"
--   openid.ALIAS.type.email:  "http://axschema.org/contact/email"
--   ...
--
-- the value of the alias may vary from request to request, depending
-- on how many extensions are enabled, but we haven't seen them vary
-- the fields. for example, if we requested the email, with the field
-- alias "email" in the request then it comes back under value.email
-- and type.email. the other libraries I've seen assume this as well
-- so we'll just go with that.
getAxAlias :: (String, String) -> Maybe String
getAxAlias (n,v) = do
  guard ("openid.ns." `isPrefixOf` n && extNamespacePrefix `isPrefixOf` v)
  return (drop (length "openid.ns.") n)
