{-# LANGUAGE ImplicitParams     #-}
{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE RankNTypes         #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE ConstraintKinds    #-}
{-# OPTIONS_GHC -fno-warn-type-defaults #-}



{- |
Module      : QuickBooks.Authentication
Description : Module for gaining Access Tokens, OAuth and OAuth2
Copyright   : Plow Technologies LLC
License     : MIT License

Maintainer  : Scott Murphy


https://developer.intuit.com/docs/0100_quickbooks_online/0100_essentials/000500_authentication_and_authorization/implement_single_sign-on_with_openid#/Initiating_the_authentication_request

https://developer.intuit.com/docs/0100_quickbooks_online/0100_essentials/000500_authentication_and_authorization/implement_single_sign-on_with_openid#/Discovery_document




-}

module QuickBooks.Authentication
  ( getTempOAuthCredentialsRequest
  , getAccessTokenRequest
  , oauthSignRequest
  , authorizationURLForToken
  , disconnectRequest
  , qbAuthGetBS
  , qbAuthPostBS
  , qbAuthPostBS'
  , fetchAccessToken
  , readOAuth2Config
  , makeOAuth2
 ) where

import           Control.Monad          (void, liftM, ap)
import           Data.Monoid            ((<>))
import           Data.Yaml              (ParseException, decodeFileEither)
import qualified Data.ByteString.Lazy   as BSL
import           Data.ByteString.Char8  (unpack, ByteString)
import           Network.HTTP.Client    (Manager
                                         ,Request(..)
                                          ,RequestBody(RequestBodyLBS,RequestBodyBS)
                                          ,requestBody
                                          ,responseBody
                                          ,parseUrlThrow
                                          ,setQueryString
                                         ,Response(..)
                                         ,httpLbs)

import           Network.HTTP.Types.URI  (parseSimpleQuery)
import           Network.URI             (escapeURIString, isUnescapedInURI)

import qualified Network.HTTP.Client.TLS as TLS

import           URI.ByteString          (serializeURIRef',URI)
import           URI.ByteString.QQ
import           Web.Authenticate.OAuth  (signOAuth
                                         ,newCredential
                                         ,emptyCredential
                                         ,injectVerifier
                                         ,newOAuth
                                         ,OAuth(..))


import           Data.Aeson
import qualified Data.Text               as T
import           Data.Text.Encoding      (encodeUtf8
                                         ,decodeUtf8)
import           QuickBooks.Logging      (logAPICall')
import           QuickBooks.Types
import qualified Network.OAuth.OAuth2    as OAuth2
import qualified Network.OAuth.OAuth2.HttpClient as OAuth2
import qualified Network.HTTP.Types      as HT
import           Control.Monad.Except


qbAuthGetBS :: Manager -> OAuth2.AccessToken
            -> URI
            -> IO (Either BSL.ByteString BSL.ByteString)
qbAuthGetBS mgr token uri = runExceptT $ OAuth2.authGetBS mgr token uri


-- | Conduct POST request for Quickbooks.

qbAuthPostBS :: (ToJSON a, ?logger::Logger)
             => Manager
             -> OAuth2.AccessToken
             -> URI
             -> a
             -> IO (Either BSL.ByteString BSL.ByteString)
qbAuthPostBS manager tok url = qbAuthPostBS' manager tok url "application/json" . RequestBodyBS . BSL.toStrict . encode

qbAuthPostBS' :: (?logger::Logger)
             => Manager
             -> OAuth2.AccessToken
             -> URI
             -> ByteString
             -> RequestBody
             -> IO (Either BSL.ByteString BSL.ByteString)
qbAuthPostBS' manager tok url contentType pb = do
  rawReq <- OAuth2.uriToRequest url
  let req = rawReq
        { requestBody = pb
        , method = "POST"
        , requestHeaders =
            [ (HT.hContentType, contentType)
            , (HT.hAccept,"application/json")
            , (HT.hAuthorization, "Bearer " <> encodeUtf8 (OAuth2.atoken tok))
            ] <> requestHeaders rawReq
        }
  logAPICall' req
  rsp <- httpLbs req manager
  pure $ if HT.statusIsSuccessful $ responseStatus rsp
    then Right $ responseBody rsp
    else Left $ responseBody rsp

--------------------------------------------------
-- OAUTH2
--------------------------------------------------
fetchAccessToken :: OAuth2Config -> IO OAuth2.OAuth2Token
fetchAccessToken oauth2Config = do
   mgr <- TLS.getGlobalManager
   let newOAuth2 = makeOAuth2 oauth2Config
   let refreshToken = OAuth2.RefreshToken $ oauthRefreshToken oauth2Config
   oauthTokenRslt <- runExceptT $ OAuth2.refreshAccessToken mgr newOAuth2 refreshToken
   case oauthTokenRslt of
     Left e       -> fail $ show e
     Right tok  -> do
       return tok

readOAuth2Config :: IO (Either String OAuth2Config)
readOAuth2Config = do
  eitherOAuth2Config <- readOAuth2ConfigFromFile $ "config/quickbooksConfig.yml"
  case eitherOAuth2Config of
    Left _ -> return $ Left "The config variables oauth2ClientId, oauth2ClientSecret, and oauth2RefreshToken must be set"
    Right config -> return $ Right config

readOAuth2ConfigFromFile :: FilePath -> IO (Either ParseException OAuth2Config)
readOAuth2ConfigFromFile = decodeFileEither

makeOAuth2 :: OAuth2Config -> OAuth2.OAuth2
makeOAuth2 config = OAuth2.OAuth2 {
    OAuth2.oauth2ClientId            = oauthClientId config
  , OAuth2.oauth2ClientSecret        = oauthClientSecret config
  , OAuth2.oauth2AuthorizeEndpoint   = [uri|https://appcenter.intuit.com/connect/obbauth2|]
  , OAuth2.oauth2TokenEndpoint       = [uri|https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer|]
  , OAuth2.oauth2RedirectUri         = [uri|https://developer.intuit.com/v2/OAuth2Playground/RedirectUrl|]
  }

-- testOAuth2 :: OAuth2.OAuth2
-- testOAuth2 = OAuth2.OAuth2 {
--     OAuth2.oauthClientId            = ""
--   , OAuth2.oauthClientSecret        = ""
--   , OAuth2.oauthOAuthorizeEndpoint  = [uri|https://appcenter.intuit.com/connect/oauth2|]
--   , OAuth2.oauthAccessTokenEndpoint = [uri|https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer|]
--   , OAuth2.oauthCallback            =  Just [uri|https://developer.intuit.com/v2/OAuth2Playground/RedirectUrl|]
--   }




-- Need to add something on the actual page to enable the token
quickbooksAuthRequest :: OAuth2.OAuth2 -> IO (Response BSL.ByteString)
quickbooksAuthRequest oauth = do
            req <- parseUrlThrow "https://appcenter.intuit.com/connect/oauth2"
            mgr <- TLS.getGlobalManager
            let newReq = setQueryString parameters req
--           return $ (getUri newReq)
            httpLbs newReq mgr

  where
    parameters = [
       ("client_id"    , Just $ encodeUtf8 . OAuth2.oauth2ClientId $ oauth )
      ,("scope"        , Just ".intuit.quickbooks.accounting openid email profile")
      ,("redirect_uri" , Just $ serializeURIRef' $ OAuth2.oauth2RedirectUri oauth)
      ,("response_type", Just "code")
      ,("state"        , Just "PlaygroundAuth")]









--------------------------------------------------
-- OAUTH
--------------------------------------------------

getTempOAuthCredentialsRequest :: ( ?logger :: Logger
                                  , ?manager :: Manager
                                  , AppEnv)
                               => CallbackURL
                               -> IO (Either String (QuickBooksResponse OAuthToken)) -- ^ Temporary OAuthToken
getTempOAuthCredentialsRequest callbackURL =
  return . handleQuickBooksTokenResponse "Couldn't get temporary tokens" =<< tokensRequest

    where
      tokensRequest = getToken temporaryTokenURL "?oauth_callback=" callbackURL oauthSignRequestWithEmptyCredentials


getAccessTokenRequest :: (?logger::Logger, ?manager::Manager, AppEnv)
                       => OAuthToken                                         -- ^ Temporary Token
                       -> OAuthVerifier                                      -- ^ OAuthVerifier provided by QuickBooks
                       -> IO (Either String (QuickBooksResponse OAuthToken)) -- ^ OAuthToken
getAccessTokenRequest  tempToken verifier =
  return.handleQuickBooksTokenResponse "Couldn't get access tokens" =<< tokensRequest
  where
    tokensRequest = getToken accessTokenURL "?oauth_token=" (unpack $ token tempToken) (oauthSignRequestWithVerifier verifier tempToken)


disconnectRequest :: (?logger::Logger, ?manager::Manager, AppEnv)
                  => OAuthToken
                  -> IO (Either String (QuickBooksResponse ()))
disconnectRequest  tok = do
  req  <- parseUrlThrow $ escapeURIString isUnescapedInURI $ disconnectURL
  req' <- oauthSignRequest tok req
  void $ httpLbs req' ?manager
  logAPICall' req'
  return $ Right QuickBooksVoidResponse

getToken :: (?logger :: Logger, ?manager::Manager, AppEnv)
          => String                  -- ^ Endpoint to request the token
          -> String                  -- ^ URL parameter name
          -> String                  -- ^ URL parameter value
          -> ((?appConfig :: AppConfig) => Request -> IO Request) -- ^ Signing function
          -> IO (Maybe OAuthToken)
getToken tokenURL parameterName parameterValue signRequest = do
  request  <- parseUrlThrow $ escapeURIString isUnescapedInURI $ concat [tokenURL, parameterName, parameterValue]
  request' <- signRequest request { method="POST", requestBody = RequestBodyLBS "" }
  response <- httpLbs request' ?manager
  logAPICall' request'
  return $ tokensFromResponse (responseBody response)

oauthSignRequestWithVerifier :: (?appConfig :: AppConfig)
                             => OAuthVerifier
                             -> OAuthToken
                             -> Request
                             -> IO Request
oauthSignRequestWithVerifier verifier tempToken = signOAuth oauthApp credsWithVerifier
  where
    credentials       = newCredential (token tempToken)
                                      (tokenSecret tempToken)
    credsWithVerifier = injectVerifier (unOAuthVerifier verifier) credentials
    oauthApp          = newOAuth { oauthConsumerKey    = consumerToken ?appConfig
                                 , oauthConsumerSecret = consumerSecret ?appConfig }

oauthSignRequest :: (?appConfig :: AppConfig)
                 => OAuthToken
                 -> Request
                 -> IO Request
oauthSignRequest tok req = signOAuth oauthApp credentials req
  where
    credentials = newCredential (token tok)
                                (tokenSecret tok)
    oauthApp    = newOAuth { oauthConsumerKey    = consumerToken ?appConfig
                           , oauthConsumerSecret = consumerSecret ?appConfig }

oauthSignRequestWithEmptyCredentials :: (?appConfig :: AppConfig)
                                     => Request
                                     -> IO Request
oauthSignRequestWithEmptyCredentials = signOAuth oauthApp credentials
  where
    credentials = emptyCredential
    oauthApp    = newOAuth { oauthConsumerKey    = consumerToken ?appConfig
                           , oauthConsumerSecret = consumerSecret ?appConfig }

disconnectURL :: String
disconnectURL = "https://appcenter.intuit.com/api/v1/connection/disconnect"

accessTokenURL :: String
accessTokenURL = "https://oauth.intuit.com/oauth/v1/get_access_token"

temporaryTokenURL :: String
temporaryTokenURL = "https://oauth.intuit.com/oauth/v1/get_request_token"

authorizationURL :: ByteString
authorizationURL = "https://appcenter.intuit.com/Connect/Begin"

authorizationURLForToken :: OAuthToken -> ByteString
authorizationURLForToken oatoken = authorizationURL <> "?oauth_token=" <> (token oatoken)

handleQuickBooksTokenResponse :: String -> Maybe OAuthToken -> Either String (QuickBooksResponse OAuthToken)
handleQuickBooksTokenResponse _ (Just tokensInResponse) = Right $ QuickBooksAuthResponse tokensInResponse
handleQuickBooksTokenResponse errorMessage Nothing      = Left errorMessage

tokensFromResponse :: BSL.ByteString -> Maybe OAuthToken
tokensFromResponse response = OAuthToken `liftM` lookup "oauth_token" responseParams
                                         `ap` lookup "oauth_token_secret" responseParams
  where responseParams = parseSimpleQuery (BSL.toStrict response)
