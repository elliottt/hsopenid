
import MonadLib
import Network.OpenID
import Network.SSL

import Network.Socket
import System.Environment

main = withSocketsDo $ do
  sslInit
  [ident,check] <- getArgs
  case normalizeIdentifier (Identifier ident) of
    Nothing -> putStrLn "Unable to normalize identifier"
    Just i  -> do
      let resolve = makeRequest True
      rpi <- discover resolve i
      case rpi of
        Left err    -> putStrLn $ "discover: " ++ show err
        Right (p,i) -> do
          putStrLn ("found provider: " ++ show p)
          putStrLn ("found identity: " ++ show i)
          eam <- associate emptyAssociationMap True resolve p
          case eam of
            Left err -> putStrLn $ "associate: " ++ show err
            Right am -> do
              let au = authenticationURI am Setup p i check Nothing
              print au
              line <- getLine
              let params = parseParams line
              print =<< verifyAuthentication am params check resolve
