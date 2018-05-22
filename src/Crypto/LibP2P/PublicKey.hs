{-|
Module      : Crypto.LibP2P.Key
Description : Short description
License     : Apache-2.0
Maintainer  : quoc.ho@matrix.ai
Stability   : experimental
Portability : POSIX

Here is a longer description of this module, containing some
commentary with @some markup@.
-}
module Crypto.LibP2P.PublicKey where

import qualified Crypto.Hash.Algorithms           as Hash
import qualified Crypto.PubKey.Ed25519            as Ed25519
import qualified Crypto.PubKey.RSA                as RSA
import qualified Crypto.PubKey.RSA.PKCS15         as RSAPKCS15
import qualified Crypto.Secp256k1                 as Secp256k1
import qualified Data.ByteString                  as BS

import           Crypto.Error                     (eitherCryptoError)

class PublicKey a where
  verify :: a
         -> BS.ByteString -- ^ Message
         -> BS.ByteString -- ^ Signature
         -> Either String Bool -- ^ Returns True if verified signature matches the message

instance PublicKey Ed25519.PublicKey where
  verify pk msgb sigb = case eitherCryptoError $ Ed25519.signature sigb of
                             Right sig -> Right $ Ed25519.verify pk msgb sig
                             -- TODO: if we fail to parse the signature, return
                             -- an Either CryptoError Bool to that effect.
                             Left e    -> Left $ show e

instance PublicKey Secp256k1.PubKey where
  verify pk msgb sigb =
    let mSig = Secp256k1.importSig sigb
        mMsg = Secp256k1.msg msgb
    in case mSig of
            Nothing -> Right False
            Just sig -> case mMsg of
                             Nothing  -> Left "Failed to parse Secp256k1 message"
                             Just msg -> Right $ Secp256k1.verifySig pk sig msg

instance PublicKey RSA.PublicKey where
  verify pk msgb sigb = Right $ RSAPKCS15.verify (Just Hash.SHA256) pk msgb sigb

