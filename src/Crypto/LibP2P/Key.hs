module Crypto.LibP2P.Key where

import qualified Crypto.PubKey.Ed25519             as Ed25519
import qualified Crypto.PubKey.RSA                 as RSA
import qualified Crypto.Secp256k1                  as Secp256k1
import Crypto.LibP2P.Protobuf.KeyType (KeyType (RSA, Ed25519, Secp256k1))
import Crypto.Random (drgNew, randomBytesGenerate)
import Crypto.Random.Types (MonadRandom)

-- TODO: Parsing is ambiguous for Ed25519 keys
-- Also issues with Secp256k1 keys that need to be debugged
-- For now, only use RSA as the keytype, and figure out
-- what to do about ambiguous parsing later
data Key
  = RSAPub        RSA.PublicKey
  | RSAPriv       RSA.PrivateKey
  deriving (Show, Eq)


-- | Explicitly defined keypairs
data KeyPair = RSAKeyPair RSA.PublicKey RSA.PrivateKey
             | Ed25519KeyPair Ed25519.PublicKey Ed25519.SecretKey
             | Secp256k1KeyPair Secp256k1.PubKey Secp256k1.SecKey
             deriving (Show, Eq)

makeRSAPubKey :: RSA.PublicKey -> Key
makeRSAPubKey k = RSAPub k

makeRSAPrivKey :: RSA.PrivateKey -> Key
makeRSAPrivKey k = RSAPriv k

-- makeEd25519PubKey :: Ed25519.PublicKey -> Key
-- makeEd25519PubKey k = Ed25519Pub k

-- makeEd25519PrivKey :: Ed25519.SecretKey -> Key
-- makeEd25519PrivKey k = Ed25519Priv k

-- makeSecp256k1PubKey :: Secp256k1.PubKey -> Key
-- makeSecp256k1PubKey k = Secp256k1Pub k

-- makeSecp256k1PrivKey  :: Secp256k1.SecKey -> Key
-- makeSecp256k1PrivKey k = Secp256k1Priv k

-- | Generate `Key` pair based on a `KeyType`
generateKeyPair :: (MonadRandom m) => KeyType ->  Int -> m KeyPair
generateKeyPair RSA b = uncurry RSAKeyPair <$> RSA.generate b e
  -- Apparently, 0x1000001 is a popular choice
  -- More information:
  -- https://security.stackexchange.com/questions/2335/should-rsa-public-exponent-be-only-in-3-5-17-257-or-65537-due-to-security-c
  where e = 65537
generateKeyPair Ed25519 _ = do
  sk <- Ed25519.generateSecretKey
  return $ Ed25519KeyPair (Ed25519.toPublic sk) sk
generateKeyPair Secp256k1 _ = do
  drg <- drgNew
  let sk = Secp256k1.secKey $ fst $ randomBytesGenerate 32 drg
  case (Secp256k1KeyPair . Secp256k1.derivePubKey <$> sk) <*> sk of
    Just x -> return x
    -- This `error` should never happen. Opting for error instead of `Maybe` return
    -- type for ease of use for the time being.
    Nothing -> error "32 byte Secp256k1 keypair failed to generate"
