<?php

    namespace Crypto\Asymmetric;

    use Crypto\Helper\CryptoException;
    use Crypto\Helper\CryptoInterface;

    class PublicSimpleCrypto implements CryptoInterface
    {
        protected string $publicKey;

        /**
         * @throws CryptoException
         */
        public function __construct(
            string $publicKey
        )
        {
            if (!preg_match("/^([-A-z ]+)\r*\n/m", $publicKey)) {
                if (!is_file($publicKey)) {
                    throw new CryptoException("public key file not found \"{$publicKey}\"", 201);
                }
                $publicKey = "file://{$publicKey}";
            }
            $this->publicKey = $publicKey;
        }

        /**
         * gets the OpenSSLAsymmetricKey ot this instance or throws a CryptoException in case of fail
         *
         * @return \OpenSSLAsymmetricKey
         * @throws CryptoException
         */
        protected function getKey(): \OpenSSLAsymmetricKey
        {
            $key = openssl_get_publickey($this->publicKey);
            if (!$key instanceof \OpenSSLAsymmetricKey) {
                throw new CryptoException("failed to create open ssl key", 202);
            }
            return $key;
        }

        /**
         * encoding the data with the public key and reruns a base64 string back or throws a CryptoException in case of failing the process
         *
         * @param string|\Stringable $data - data that has to encoded
         * @return string - base64 string
         * @throws CryptoException
         */
        public function encode(string|\Stringable $data): string
        {
            $dataChunks = str_split((string) $data, self::ENCRYPT_BLOCK_SIZE);

            $output = array_reduce(
                $dataChunks,
                function (string $carry, string $chunk): string {
                    $chunkOutput = "";
                    $encodeProcess = openssl_public_encrypt(
                        $chunk,
                        $chunkOutput,
                        $this->getKey(),
                        OPENSSL_SSLV23_PADDING
                    );
                    if (!$encodeProcess) {
                        $errorMsg = openssl_error_string();
                        throw new CryptoException("fail to encode: \"{$errorMsg}\"", 203);
                    }
                    return $carry.$chunkOutput;
                },
                ""
            );
            return base64_encode($output);
        }

        /**
         * decoding the base64Cipher with the private key and reruns a string back or throws a CryptoException in case of failing the process
         *
         * @param string $base64Cipher
         * @return string
         * @throws CryptoException
         */
        public function decode(string $base64Cipher): string
        {
            $cipher = base64_decode($base64Cipher);
            if (!is_string($cipher)) {
                throw new CryptoException("fail to encode base64", 204);
            }

            $cipherChunks = str_split($cipher, self::DECRYPT_BLOCK_SIZE);

            return array_reduce(
                $cipherChunks,
                function (string $carry, string $cipherChunk): string {
                    $chunkOutput = "";
                    $decryptProcess = openssl_public_decrypt(
                        $cipherChunk,
                        $chunkOutput,
                        $this->getKey()
                    );
                    if (!$decryptProcess) {
                        $errorMsg = openssl_error_string();
                        throw new CryptoException("fail to decode: \"{$errorMsg}\"", 205);
                    }
                    return $carry.$chunkOutput;
                },
                ""
            );
        }

    }