{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE ScopedTypeVariables    #-}
{-|
Description : Tests for hs-libp2p-crypto
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
import           Crypto.LibP2P.Protobuf.KeyType

import qualified Crypto.PubKey.Ed25519      as Ed25519
import qualified Crypto.PubKey.RSA          as RSA
import qualified Crypto.Secp256k1           as Secp256k1
import qualified Data.ByteArray             as BA
import qualified Data.ByteString            as BS

import           Control.Monad              (replicateM)
import           Crypto.Random.Types        (MonadRandom (..))
import           Data.Proxy                 (Proxy (..))
import           Data.Word                  (Word8)
import           Test.QuickCheck.Gen        (Gen, chooseAny)
import           Test.Tasty
import qualified Test.Tasty.QuickCheck      as QC
import qualified Test.Tasty.HUnit           as HU

newtype TestGen a = TestGen { unTestGen :: (Gen a) } deriving (Monad, Functor, Applicative)
instance MonadRandom TestGen where
  getRandomBytes n = do
    w <- TestGen $ replicateM n $ (chooseAny :: Gen Word8)
    return $ BA.pack w

newtype Ed25519PublicKey = Ed25519PublicKey Ed25519.PublicKey deriving (Show)
instance QC.Arbitrary Ed25519PublicKey where
  arbitrary = do
    sk <- unTestGen $ Ed25519.generateSecretKey
    return $ Ed25519PublicKey $ Ed25519.toPublic sk

newtype Ed25519SecretKey = Ed25519SecretKey Ed25519.SecretKey deriving (Show)
instance QC.Arbitrary Ed25519SecretKey where
  arbitrary = do
    sk <- unTestGen $ Ed25519.generateSecretKey
    return $ Ed25519SecretKey sk

newtype RSAPublicKey = RSAPublicKey { unRSAPublicKey :: RSA.PublicKey } deriving (Show)
instance QC.Arbitrary RSAPublicKey where
  arbitrary = do
    (pk, _) <- unTestGen $ RSA.generate 128 65537
    return $ RSAPublicKey pk

newtype RSAPrivateKey = RSAPrivateKey { unRSAPrivateKey :: RSA.PrivateKey } deriving (Show)
instance QC.Arbitrary RSAPrivateKey where
  arbitrary = do
    (_, sk) <- unTestGen $ RSA.generate 128 65537
    return $ RSAPrivateKey sk

newtype TestKey = TestKey Key deriving Show
instance QC.Arbitrary TestKey where
  arbitrary = do
    TestKey <$> QC.oneof keys
      where
        keys :: [Gen Key]
        keys =
          [ QC.arbitrary >>= return . makeRSAPubKey . unRSAPublicKey
          , QC.arbitrary >>= return . makeRSAPrivKey . unRSAPrivateKey ]
          -- , QC.arbitrary >>= return . makeEd25519PubKey
          -- , QC.arbitrary >>= return . makeEd25519PrivKey
          -- , QC.arbitrary >>= return . makeSecp256k1PubKey
          -- , QC.arbitrary >>= return . makeSecp256k1PrivKey ]

newtype TestKeyPair = TestKeyPair KeyPair deriving Show
instance QC.Arbitrary TestKeyPair where
  arbitrary = do
    kt <- QC.elements [RSA, Ed25519]
    b <- QC.elements [1024]
    kp <- unTestGen $ generateKeyPair kt b
    return $ TestKeyPair kp

--prop_PublicKeyIsDerivable :: TestKeyPair -> Bool
--prop_PublicKeyIsDerivable (TestKeyPair (RSAKeyPair pk sk)) = toPublic sk == pk
--prop_PublicKeyIsDerivable (TestKeyPair (Ed25519KeyPair pk sk)) = toPublic sk == pk
--prop_PublicKeyIsDerivable (TestKeyPair (Secp256k1KeyPair pk sk)) = toPublic sk == pk

test_PublicKeyIsDerivable :: KeyType -> Int -> HU.Assertion
test_PublicKeyIsDerivable kt b = do
  kp <- generateKeyPair kt b
  HU.assertBool "Not true" $ testToPublic' kp
  where
    testToPublic' (RSAKeyPair pk sk) = toPublic sk == pk
    testToPublic' (Secp256k1KeyPair pk sk) = toPublic sk == pk
    testToPublic' (Ed25519KeyPair pk sk) = toPublic sk == pk

prop_KeySignature :: (PrivateKey a b) => a -> [Word8] -> Bool
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

prop_KeyEncoding :: TestKey -> Bool
prop_KeyEncoding (TestKey k) = k == getk2
  where
    getk2 :: Key
    getk2 = case parseKey $ serialize k of
                 Right k' -> k'
                 _ -> error "failed"

class (PrivateKey a b, Show a, QC.Arbitrary a) => TestPrivKey a b where
  testPrivKey :: String -> Proxy a -> TestTree
  testPrivKey keyStr _ = QC.testProperty ("(verify signature == True) for " ++ keyStr) (prop_KeySignature :: a -> [Word8] -> Bool)

--    TQC.testProperty "verify pk msg (sign sk msg) == True"
instance PrivateKey RSAPrivateKey RSA.PublicKey where
  sign (RSAPrivateKey k) d = sign k d
  toPublic (RSAPrivateKey k) = toPublic k
instance TestPrivKey RSAPrivateKey RSA.PublicKey

instance PrivateKey Ed25519SecretKey Ed25519.PublicKey where
  sign (Ed25519SecretKey k) d = sign k d
  toPublic (Ed25519SecretKey k) = toPublic k
instance TestPrivKey Ed25519SecretKey Ed25519.PublicKey

instance TestPrivKey Secp256k1.SecKey Secp256k1.PubKey

main :: IO ()
main = defaultMain $ testGroup "Tests" [ testGroup "Property tests" [qcProps]
                                       , testGroup "Unit tests" [unitTests]
                                       ]

qcProps :: TestTree
qcProps = testGroup "(checked by QuickCheck)"
  [ QC.testProperty "parseKey (serialize key) == key" prop_KeyEncoding
  , testPrivKey "RSAPrivateKey" (Proxy :: Proxy RSAPrivateKey)
  , testPrivKey "Ed25519SecretKey" (Proxy :: Proxy Ed25519SecretKey)
  --, QC.testProperty "toPublic sk == pk" prop_PublicKeyIsDerivable
  ]

unitTests :: TestTree
unitTests = testGroup "(checked by hspec)"
  [ HU.testCase "RSA" $ test_PublicKeyIsDerivable RSA 1024
  , HU.testCase "Ed25519" $ test_PublicKeyIsDerivable Ed25519 1024
  , HU.testCase "Secp256k1" $ test_PublicKeyIsDerivable Secp256k1 1024
  ]

  -- TODO: Secp256k1 secret keys require a specific message type
  -- which doesn't test well with our randomly generated bytes
  -- used to test message signing. Not sure how to pass in this
  -- message type to the tests at the moment, suggestions welcome
  --testPrivKey (Proxy :: Proxy Secp256k1.SecKey)
