module Network.OpenID.Response where

-- Friends
import Network.OpenID.Types

-- Libraries
import Data.List
import Data.Maybe


-- | Turn a response body into a list of parameters.
parseDirectResponse :: String -> Params
parseDirectResponse  = unfoldr step
  where
    step str = case break (== '\n') str of
      (_,[])      -> Nothing
      (ps,_:rest) -> case break (== ':') ps of
        (_,[]) -> Nothing
        (k,_:v) -> Just ((k,v),rest)
