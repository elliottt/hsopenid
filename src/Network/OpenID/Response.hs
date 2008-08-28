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
    step []  = Nothing
    step str = case break (== '\n') str of
      (ps,[])     -> Just (f ps,[])
      (ps,_:rest) -> Just (f ps,rest)
      where
        f ps = case break (== ':') ps of
          (k,[])  -> (k,[])
          (k,_:v) -> (k,v)
