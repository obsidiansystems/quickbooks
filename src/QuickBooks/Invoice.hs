{-# LANGUAGE ConstraintKinds   #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE ImplicitParams    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PolyKinds         #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RankNTypes        #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeOperators     #-}
{-# LANGUAGE ScopedTypeVariables #-}
------------------------------------------------------------------------------
-- |
-- Module      : QuickBooks.Requests
-- Description :
-- Copyright   :
-- License     :
-- Maintainer  :
-- Stability   :
-- Portability :
--
--
--
------------------------------------------------------------------------------

module QuickBooks.Invoice
 ( createInvoiceRequest
 , readInvoiceRequest
 , updateInvoiceRequest
 , deleteInvoiceRequest
 , sendInvoiceRequest
 , uploadAttachmentToInvoice
 , getInvoiceNumbersWithPrefix
 ) where

import qualified Network.OAuth.OAuth2      as OAuth2
import qualified Text.Email.Validate       as Email (EmailAddress, toByteString)

import           Data.ByteString.Char8
import qualified Data.ByteString.Lazy
import qualified Data.ByteString.Lazy.Char8
import           Data.Aeson                (encode, eitherDecode, object, Value(String), ToJSON (..), FromJSON, (.=), (.:), (.:?))
import           Data.Aeson.Types (parseEither, withObject)
import           Data.String.Interpolate   (i)
import           Network.HTTP.Client       (httpLbs
                                           ,parseUrlThrow
                                           ,Request(..)
                                           ,RequestBody(..)
                                           ,Response(responseBody))
import           Network.HTTP.Types.Header (hAccept,hContentType)
import           Network.URI               ( escapeURIString
                                           , isUnescapedInURI
                                           , isUnescapedInURIComponent
                                           )
import           URI.ByteString

import           QuickBooks.Authentication
import           QuickBooks.Types

import Control.Monad
import QuickBooks.Logging  (logAPICall)
import Network.HTTP.Client.MultipartFormData
import Data.Text (Text)
import GHC.Generics
import Data.Text.Encoding
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Maybe (fromMaybe)

-- | Create an invoice.
createInvoiceRequest :: APIEnv
                     => OAuthTokens
                     -> Invoice
                     -> IO (Either String (QuickBooksResponse Invoice))
createInvoiceRequest tok = postInvoice tok

-- | Update an invoice.
updateInvoiceRequest :: APIEnv
                     => OAuthTokens
                     -> Invoice
                     -> IO (Either String (QuickBooksResponse Invoice))
updateInvoiceRequest tok = postInvoice tok

-- | Read an invoice.
readInvoiceRequest :: APIEnv
                   => OAuthTokens
                   -> InvoiceId
                   -> IO (Either String (QuickBooksResponse Invoice))
readInvoiceRequest (OAuth1 tok) iId = readInvoiceRequestOAuth tok iId
readInvoiceRequest (OAuth2 tok) iId = readInvoiceRequestOAuth2 tok iId

--- OAuth 1 ---
readInvoiceRequestOAuth :: APIEnv
                   => OAuthToken
                   -> InvoiceId
                   -> IO (Either String (QuickBooksResponse Invoice))
readInvoiceRequestOAuth tok iId = do
  let apiConfig = ?apiConfig
  req  <- oauthSignRequest tok =<< parseUrlThrow (escapeURIString isUnescapedInURI [i|#{invoiceURITemplate apiConfig}#{unInvoiceId iId}?minorversion=63|])
  let oauthHeaders = requestHeaders req
  let req' = req{method = "GET", requestHeaders = oauthHeaders ++ [(hAccept, "application/json")]}
  resp <-  httpLbs req' ?manager
  logAPICall req'
  return $ eitherDecode $ responseBody resp

--- OAuth 2 ---
readInvoiceRequestOAuth2 :: APIEnv
                   => OAuth2.AccessToken
                   -> InvoiceId
                   -> IO (Either String (QuickBooksResponse Invoice))
readInvoiceRequestOAuth2 tok iId = do
  let apiConfig = ?apiConfig
  let eitherQueryURI = parseURI strictURIParserOptions . pack $ [i|#{invoiceURITemplate apiConfig}#{unInvoiceId iId}?minorversion=63|]
  -- Made for logging
  req' <- parseUrlThrow (escapeURIString isUnescapedInURI [i|#{invoiceURITemplate apiConfig}#{unInvoiceId iId}?minorversion=63|])
  case eitherQueryURI of
    Left err -> return (Left . show $ err)
    Right queryURI -> do
      -- Make the call
      eitherResponse <- qbAuthGetBS ?manager tok queryURI
      logAPICall req'
      case eitherResponse of
        (Left err) -> return (Left . show $ err)
        (Right resp) -> do
          Data.ByteString.Lazy.Char8.putStrLn resp
          return $ eitherDecode resp


-- | Delete an invoice.
deleteInvoiceRequest :: APIEnv
                     => OAuthTokens
                     -> InvoiceId
                     -> SyncToken
                     -> IO (Either String (QuickBooksResponse DeletedInvoice))
deleteInvoiceRequest (OAuth1 tok) iId syncToken = deleteInvoiceRequestOAuth tok iId syncToken
deleteInvoiceRequest (OAuth2 tok) iId syncToken = deleteInvoiceRequestOAuth2 tok iId syncToken


--- OAuth 1 ---
deleteInvoiceRequestOAuth :: APIEnv
                     => OAuthToken
                     -> InvoiceId
                     -> SyncToken
                     -> IO (Either String (QuickBooksResponse DeletedInvoice))
deleteInvoiceRequestOAuth tok iId syncToken = do
  let apiConfig = ?apiConfig
  req  <- parseUrlThrow $ escapeURIString isUnescapedInURI [i|#{invoiceURITemplate apiConfig}?operation=delete|]
  req' <- oauthSignRequest tok req{ method = "POST"
                                  , requestBody    = RequestBodyLBS $ encode body
                                  , requestHeaders = [ (hAccept, "application/json")
                                                     , (hContentType, "application/json")
                                                     ]
                                  }
  resp <-  httpLbs req' ?manager
  logAPICall req'
  return $ eitherDecode $ responseBody resp
  where
    body = object [ ("Id", String (unInvoiceId iId))
                  , ("SyncToken", String (unSyncToken syncToken))
                  ]

--- OAuth 2 ---
deleteInvoiceRequestOAuth2 :: APIEnv
                     => OAuth2.AccessToken
                     -> InvoiceId
                     -> SyncToken
                     -> IO (Either String (QuickBooksResponse DeletedInvoice))
deleteInvoiceRequestOAuth2 tok iId syncToken = do
  let apiConfig = ?apiConfig
  let eitherQueryURI = parseURI strictURIParserOptions . pack $ [i|#{invoiceURITemplate apiConfig}?operation=delete|]
  -- Made for logging
  req'  <- parseUrlThrow $ escapeURIString isUnescapedInURI [i|#{invoiceURITemplate apiConfig}?operation=delete|]
  case eitherQueryURI of
    Left err -> return (Left . show $ err)
    Right queryURI -> do
      -- Make the call
      eitherResponse <- qbAuthPostBS ?manager tok queryURI body
      logAPICall req'
      case eitherResponse of
        (Left err) -> return (Left . show $ err)
        (Right resp) -> do
          return $ eitherDecode resp
  where
    body = object [ ("Id", String (unInvoiceId iId))
                  , ("SyncToken", String (unSyncToken syncToken))
                  ]

-- | email and invoice
sendInvoiceRequest :: APIEnv
                   => OAuthTokens
                   -> InvoiceId
                   -> Email.EmailAddress
                   -> IO (Either String (QuickBooksResponse Invoice))
sendInvoiceRequest (OAuth1 tok) iId emailAddr = sendInvoiceRequestOAuth tok iId emailAddr
sendInvoiceRequest (OAuth2 tok) iId emailAddr = return $ Left "Not implemented " -- sendInvoiceRequestOAuth2 tok iId emailAddr

--- OAuth 1 ---
sendInvoiceRequestOAuth :: APIEnv
                   => OAuthToken
                   -> InvoiceId
                   -> Email.EmailAddress
                   -> IO (Either String (QuickBooksResponse Invoice))
sendInvoiceRequestOAuth tok iId emailAddr =  do
  let apiConfig = ?apiConfig
  req  <- parseUrlThrow $ escapeURIString isUnescapedInURI [i|#{invoiceURITemplate apiConfig}#{unInvoiceId iId}/send?sendTo=#{Email.toByteString emailAddr}|]
  req' <- oauthSignRequest tok req{ method = "POST"
                                  , requestHeaders = [ (hAccept, "application/json")
                                                     ]
                                  }
  logAPICall req'
  resp <-  httpLbs req' ?manager
  return $ eitherDecode $ responseBody resp

invoiceURITemplate :: APIConfig -> String
invoiceURITemplate APIConfig{..} = [i|https://#{hostname}/v3/company/#{companyId}/invoice/|]

--- OAuth 2 ---
-- sendInvoiceRequestOAuth2 :: APIEnv
--                    => OAuth2.AccessToken
--                    -> InvoiceId
--                    -> Email.EmailAddress
--                    -> IO (Either String (QuickBooksResponse Invoice))
-- sendInvoiceRequestOAuth2 tok iId emailAddr =  do
--   let apiConfig = ?apiConfig
--   let eitherQueryURI = parseURI strictURIParserOptions . pack $ [i|#{invoiceURITemplate apiConfig}#{unInvoiceId iId}/send?sendTo=#{Email.toByteString emailAddr}|]
--   -- Made for logging
--   req'  <- parseUrlThrow $ escapeURIString isUnescapedInURI [i|#{invoiceURITemplate apiConfig}#{unInvoiceId iId}/send?sendTo=#{Email.toByteString emailAddr}|]
--   case eitherQueryURI of
--     Left err -> return (Left . show $ err)
--     Right queryURI -> do
--       -- Make the call
--       eitherResponse <- qbAuthPostBS ?manager tok queryURI ------ !!! Something goes here !!! -------
--       logAPICall req'
--       case eitherResponse of
--         (Left err) -> return (Left . show $ err)
--         (Right resp) -> do
--           return $ eitherDecode resp

-- invoiceURITemplate :: APIConfig -> String
-- invoiceURITemplate APIConfig{..} = [i|https://#{hostname}/v3/company/#{companyId}/invoice/|]


----- Post Invoice -----
postInvoice :: APIEnv
            => OAuthTokens
            -> Invoice
            -> IO (Either String (QuickBooksResponse Invoice))
postInvoice (OAuth1 tok) invoice = postInvoiceOAuth tok invoice
postInvoice (OAuth2 tok) invoice = postInvoiceOAuth2 tok invoice

--- OAuth 1 ---
postInvoiceOAuth :: APIEnv
            => OAuthToken
            -> Invoice
            -> IO (Either String (QuickBooksResponse Invoice))
postInvoiceOAuth tok invoice = do
  let apiConfig = ?apiConfig
  req <- parseUrlThrow $ escapeURIString isUnescapedInURI [i|#{invoiceURITemplate apiConfig}?minorversion=63|]
  req' <- oauthSignRequest tok req{ method         = "POST"
                                  , requestBody    = RequestBodyLBS $ encode invoice
                                  , requestHeaders = [ (hAccept, "application/json")
                                                     , (hContentType, "application/json")
                                                     ]
                                  }
  resp <- httpLbs req' ?manager
  logAPICall req'
  return $ eitherDecode $ responseBody resp

--- OAuth 2 ---
postInvoiceOAuth2 :: APIEnv
            => OAuth2.AccessToken
            -> Invoice
            -> IO (Either String (QuickBooksResponse Invoice))
postInvoiceOAuth2 tok invoice = do
  let apiConfig = ?apiConfig
  let eitherQueryURI = parseURI strictURIParserOptions . pack $ [i|#{invoiceURITemplate apiConfig}?minorversion=63|]
  case eitherQueryURI of
    Left err -> return (Left . show $ err)
    Right queryURI -> do
      -- Make the call
      eitherResponse <- qbAuthPostBS ?manager tok queryURI invoice
      case eitherResponse of
        (Left err) -> return (Left . show $ err)
        (Right resp) -> do
          return $ eitherDecode resp

uploadURITemplate :: APIConfig -> String
uploadURITemplate APIConfig{..} = [i|https://#{hostname}/v3/company/#{companyId}/upload|]

uploadAttachmentToInvoice
  :: APIEnv
  => OAuth2.AccessToken
  -> FilePath
  -> ByteString
  -> Bool
  -> ByteString
  -> InvoiceId -- NOTE: Attachments can be uploaded to things other than invoices, but we don't have a type for that yet
  -> IO (Either String Value)
uploadAttachmentToInvoice tok fileName mimeType includeOnSend fileData invoiceId = do
  let apiConfig = ?apiConfig
  let eitherUploadURI = parseURI strictURIParserOptions . pack $ [i|#{uploadURITemplate apiConfig}?minorversion=63|]
  case eitherUploadURI of
    Left err -> return (Left . show $ err)
    Right uploadURI -> do
      boundary <- webkitBoundary
      let metadata = Data.ByteString.Lazy.toStrict $ encode $ object
            [ "FileName" .= fileName
            , "ContentType" .= decodeUtf8 mimeType
            , "AttachableRef" .=
              [ object
                [ "EntityRef" .= object
                  [ "type" .= ("Invoice" :: Text)
                  , "value" .= invoiceId
                  ]
                , "IncludeOnSend" .= includeOnSend
                ]
              ]
            ]
      body <- renderParts boundary
        [ partBS "file_metadata_0" metadata `addPartHeaders`
          [ ("Content-Type", "application/json")
          ]
        , partFileRequestBody "file_content_0" fileName (RequestBodyBS fileData) `addPartHeaders`
          [ ("Content-Type", mimeType)
          ]
        ]
      eitherResponse <- qbAuthPostBS' ?manager tok uploadURI ("multipart/form-data; boundary=" <> boundary) body
      case eitherResponse of
        (Left err) -> return (Left . show $ err)
        (Right resp) -> do
          return $ eitherDecode resp

--TODO: Make this work if there is a large number of results
getInvoiceNumbersWithPrefix
  :: APIEnv
  => OAuth2.AccessToken
  -> Text -- Should only contain characters that are legal in invoice IDs
  -> IO (Either String (Set Text))
getInvoiceNumbersWithPrefix tok prefix = do
  let apiConfig = ?apiConfig
  let query = [i|SELECT DocNumber FROM Invoice WHERE DocNumber LIKE '#{prefix}%' ORDERBY DocNumber STARTPOSITION 1 MAXRESULTS 1000|]
  let uriComponent = escapeURIString isUnescapedInURIComponent [i|#{query}|]
  let eitherQueryURI = parseURI strictURIParserOptions . pack $ [i|#{queryURITemplate apiConfig}#{uriComponent}|]
  -- Made for providing an error log
  req' <- parseUrlThrow [i|#{queryURITemplate apiConfig}#{uriComponent}|]
  case eitherQueryURI of
    Left err -> pure $ Left $ show err
    Right queryURI -> do
      -- Make the call
      eitherResponse <- qbAuthGetBS ?manager tok queryURI
      logAPICall req'
      case eitherResponse of
        Left err -> pure $ Left $ show err
        Right resp -> pure $ case eitherDecode resp of
          Left err -> Left err
          Right v -> flip parseEither v $ withObject "QuickBooks Query" $ \o -> do
            rVal <- o .: "QueryResponse"
            let parseQueryResponse rObj = do
                  invoices :: [Value] <- fmap (fromMaybe []) $ rObj .:? "Invoice"
                  docNumbers <- forM invoices $ withObject "sparse Invoice" $ \invoice -> do
                    invoice .: "DocNumber"
                  pure $ Set.fromList docNumbers
            withObject "QueryResponse" parseQueryResponse rVal

-- Template for queries
queryURITemplate :: APIConfig -> String
queryURITemplate APIConfig{..} =
  [i|https://#{hostname}/v3/company/#{companyId}/query?query=|]
