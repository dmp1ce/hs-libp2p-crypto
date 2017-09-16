{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE ScopedTypeVariables    #-}
{-|
Description : QuickCheck Tests for hs-libp2p-crypto
License     : Apache-2.0
Maintainer  : quoc.ho@matrix.ai
Stability   : experimental
Portability : POSIX

TODO: description
-}

import           Crypto.LibP2P.Key
import           Crypto.LibP2P.Parse
import           Crypto.LibP2P.PublicKey
import           Crypto.LibP2P.PrivateKey
import           Crypto.LibP2P.Serialize

import qualified Crypto.PubKey.Ed25519      as Ed25519
import qualified Crypto.PubKey.RSA          as RSA
import qualified Crypto.Secp256k1           as Secp256k1
import qualified Data.ByteArray             as BA
import qualified Data.ByteString            as BS
import qualified Test.QuickCheck            as QC

import           Control.Monad              (replicateM)
import           Crypto.Random.Types        (MonadRandom (..))
import           Data.Proxy                 (Proxy (..))
import           Data.Word                  (Word8)
import           Data.Attoparsec.ByteString (IResult (..))
import           Test.QuickCheck.Gen        (Gen, chooseAny)

instance MonadRandom Gen where
  getRandomBytes n = do
    words <- replicateM n $ (chooseAny :: Gen Word8)
    return $ BA.pack words

instance QC.Arbitrary Ed25519.PublicKey where
  arbitrary = do
    sk <- Ed25519.generateSecretKey
    return $ Ed25519.toPublic sk

instance QC.Arbitrary Ed25519.SecretKey where
  arbitrary = do
    sk <- Ed25519.generateSecretKey
    return sk

instance QC.Arbitrary RSA.PublicKey where
  arbitrary = do
    (pk, sk) <- RSA.generate 128 65537
    return pk

instance QC.Arbitrary RSA.PrivateKey where
  arbitrary = do
    (pk, sk) <- RSA.generate 128 65537
    return sk

instance QC.Arbitrary Key where
  arbitrary = do 
    QC.oneof keys
      where
        keys :: [Gen Key]
        keys = 
          [ QC.arbitrary >>= return . makeRSAPubKey
          , QC.arbitrary >>= return . makeRSAPrivKey ]
          -- , QC.arbitrary >>= return . makeEd25519PubKey
          -- , QC.arbitrary >>= return . makeEd25519PrivKey
          -- , QC.arbitrary >>= return . makeSecp256k1PubKey
          -- , QC.arbitrary >>= return . makeSecp256k1PrivKey ]

prop_KeySignature :: (PrivateKey a b,
                       Show a,
                       QC.Arbitrary a) =>
                       a -> [Word8] -> Bool
prop_KeySignature sk bytes =
  case verify pk msg sig of
       Left e  -> error e
       Right b -> b
  where
    pk  = toPublic sk
    msg = BS.pack bytes
    sig = case sign sk msg of
                Left e  -> error e
                Right s -> s

prop_KeyEncoding :: Key -> Bool
prop_KeyEncoding k = k == getk2
  where
    getk2 :: Key
    getk2 = case parseKey $ serialize k of
                 Right k -> k
                 _ -> error "failed"

class (PrivateKey a b, Show a, QC.Arbitrary a) => TestPrivKey a b where
  testPrivKey :: Proxy a -> IO ()
  testPrivKey _ = do
    QC.quickCheck
    $ (prop_KeySignature :: a -> [Word8] -> Bool)

instance TestPrivKey RSA.PrivateKey RSA.PublicKey
instance TestPrivKey Ed25519.SecretKey Ed25519.PublicKey
instance TestPrivKey Secp256k1.SecKey Secp256k1.PubKey

main :: IO ()
main = do
  QC.quickCheck $ prop_KeyEncoding
  
  testPrivKey (Proxy :: Proxy RSA.PrivateKey)
  testPrivKey (Proxy :: Proxy Ed25519.SecretKey)

  -- TODO: Secp256k1 secret keys require a specific message type
  -- which doesn't test well with our randomly generated bytes
  -- used to test message signing. Not sure how to pass in this
  -- message type to the tests at the moment, suggestions welcome
  --testPrivKey (Proxy :: Proxy Secp256k1.SecKey)
