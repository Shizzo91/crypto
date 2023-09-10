<?php

    namespace Crypto\Asymmetric;

    use Crypto\Helper\CryptoException;
    use Crypto\Helper\CryptoInterface;

    class PrivateSimpleCrypto implements CryptoInterface
    {
        protected $privateKey;
        protected $passphrase;

        /**
         * @throws CryptoException
         */
        public function __construct(
            string $privateKey,
            ?string $passphrase = null
        ){
            $this->passphrase = $passphrase;
            if (!preg_match("/^([-A-z ]+)\r*\n/m", $privateKey)) {
                if (!is_file($privateKey)) {
                    throw new CryptoException("private key file not found \"{$privateKey}\"", 101);
                }
                $privateKey = "file://{$privateKey}";
            }
            $key = openssl_pkey_get_private($privateKey, $this->passphrase);
            if ($key === false) {
                throw new CryptoException("failed to create open ssl key", 102);
            }
            $this->privateKey = $key;
        }

        /**
         * encoding the data with the private key and reruns a base64 string back or throws a CryptoException in case of failing the process
         *
         * @param string $data - data that has to encoded
         * @return string - base64 string
         * @throws CryptoException
         */
        public function encode(string $data): string
        {
            $dataChunks = str_split((string) $data, self::ENCRYPT_BLOCK_SIZE);
            $output = array_reduce(
                $dataChunks,
                function (string $carry, string $chunk): string {
                    $chunkOutput = "";
                    $encodeProcess = openssl_private_encrypt(
                        $chunk,
                        $chunkOutput,
                        $this->privateKey
                    );
                    if (!$encodeProcess) {
                        $errorMsg = openssl_error_string();
                        throw new CryptoException("fail to encode: \"{$errorMsg}\"", 103);
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
                throw new CryptoException("fail to encode base64", 104);
            }

            $cipherChunks = str_split($cipher, self::DECRYPT_BLOCK_SIZE);

            return array_reduce(
                $cipherChunks,
                function (string $carry, string $cipherChunk): string {
                    $chunkOutput = "";
                    $decryptProcess = openssl_private_decrypt(
                        $cipherChunk,
                        $chunkOutput,
                        $this->privateKey
                    );
                    if (!$decryptProcess) {
                        $errorMsg = openssl_error_string();
                        throw new CryptoException("fail to decode: \"{$errorMsg}\"", 105);
                    }
                    return $carry.$chunkOutput;
                },
                ""
            );
        }
    }