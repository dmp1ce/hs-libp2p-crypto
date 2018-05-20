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
import           Crypto.LibP2P.Protobuf.KeyType
import qualified Data.ByteString as BS
import           Data.ByteArray

runBenchmarkSign :: (PrivateKey a b) => a -> Int -> IO BS.ByteString
runBenchmarkSign sk numBytes = do
  someData <- allocByteString numBytes
  case sign sk someData of
    Left e -> error e
    Right c -> return c
  where
    allocByteString :: Int -> IO BS.ByteString
    allocByteString i = snd <$> allocRet i (const $ return ())

main :: IO ()
main = do
  putStrLn "" >> putStr "Generating keys ."
  RSAKeyPair _ rsa1024 <- generateKeyPair RSA 1024
  putStr "." >> putStrLn ""
  Ed25519KeyPair _ ed25519 <- generateKeyPair Ed25519 undefined

  let byteSizeMax = 5
  defaultMain
    [ bgroup "generateKeyPair" $
      benchSignCases "RSA 1024" byteSizeMax rsa1024
   ++ benchSignCases "Ed25519" byteSizeMax ed25519
    ]
  where
    benchSignCases :: (PrivateKey a b) => String -> Int -> a -> [Benchmark]
    benchSignCases s m key =
      [ bench (s ++ " " ++ show x ++ "B") $ whnfIO $ runBenchmarkSign key x
          | k <- [0..m], x <- [10^(k::Int)] ]
