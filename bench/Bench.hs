{-|
Description : Benchmarks for hs-libp2p-crypto
License     : Apache-2.0
Maintainer  : daveparrish@tutanota.com
Stability   : experimental
Portability : POSIX

Benchmark libp2p-crypto using Criterion and based from Go benchmarks.
-}

import           Prelude
import           Criterion.Main
import           Crypto.LibP2P.Key
import           Crypto.LibP2P.PrivateKey
import           Crypto.LibP2P.PublicKey
import           Crypto.LibP2P.Protobuf.KeyType
import qualified Data.ByteString as BS
import           Data.ByteArray

runBenchmarkSign :: (PrivateKey a b) => a -> BS.ByteString -> BS.ByteString
runBenchmarkSign sk someData = case sign sk someData of
    Left e -> error e
    Right c -> c

runBenchmarkVerify :: (PublicKey a) => a -> BS.ByteString -> BS.ByteString -> Bool
runBenchmarkVerify pk msg sig = case verify pk msg sig of
    Left e -> error e
    Right c -> c

allocByteString :: Int -> IO BS.ByteString
allocByteString i = snd <$> allocRet i (const $ return ())

main :: IO ()
main = do
  putStrLn "" >> putStr "Generating keys ."
  RSAKeyPair rsa1024pub rsa1024 <- generateKeyPair RSA 1024
  putStr "." >> putStrLn ""
  Ed25519KeyPair ed25519pub ed25519 <- generateKeyPair Ed25519 undefined

  let byteSizeMax = 5
  allBenchSignCases <- (++) <$> benchSignCases "RSA 1024" byteSizeMax rsa1024
                            <*> benchSignCases "Ed25519" byteSizeMax ed25519
  allBenchVerifyCases <- (++) <$> benchVerifyCases "RSA 1024" byteSizeMax rsa1024pub rsa1024
                              <*> benchVerifyCases "Ed25519" byteSizeMax ed25519pub ed25519

  defaultMain [ bgroup "Sign" allBenchSignCases
              , bgroup "Verify" allBenchVerifyCases
              ]
  where
    benchSignCases :: (PrivateKey a b) => String -> Int -> a -> IO [Benchmark]
    benchSignCases s m key = sequence
      [ do
           msg <- allocByteString x
           return $ bench (s ++ " " ++ show x ++ "B") $ whnf (runBenchmarkSign key) msg
      | k <- [0..m], x <- [10^(k::Int)] ]

    benchVerifyCases :: (PrivateKey a b) => String -> Int -> b -> a -> IO [Benchmark]
    benchVerifyCases groupStr maxBytes pk sk = sequence
      [ do
           msg <- allocByteString x
           case sign sk msg of
             Left e -> error e
             Right sig ->
               return $ bench (groupStr ++ " " ++ show x ++ "B") $ whnf (runBenchmarkVerify pk msg) sig
      | k <- [0..maxBytes], x <- [10^(k::Int)] ]
