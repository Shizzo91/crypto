<?php

    namespace Crypto\Single;

    use Crypto\Helper\CryptoError;
    use Crypto\Helper\CryptoInterface;

    class PrivateCrypto implements CryptoInterface
    {
        protected string $privateKey;
        public function __construct(
            string $privateKey,
            protected ?string $passphrase = null
        ){
            if (!preg_match("/^([-A-z ]+)\r*\n/m", $privateKey)) {
                if (!is_file($privateKey)) {
                    throw new CryptoError("private key file not found \"{$privateKey}\"");
                }
                $privateKey = "file://{$privateKey}";
            }
            $this->$privateKey = $privateKey;
        }

        private function getKey(): \OpenSSLAsymmetricKey
        {
            $key = openssl_pkey_get_private($this->privateKey, $this->passphrase);
            if (!$key instanceof \OpenSSLAsymmetricKey) {
                throw new CryptoError("");
            }
            return $key;
        }
        public function encode(string|\Stringable $data): string
        {
            $output = "";
            $encodeProcess = openssl_private_encrypt(
                (string) $data,
                $output,
                $this->getKey()
            );
            if (!$encodeProcess) {
                throw new CryptoError("");
            }
            return base64_encode($output);
        }

        public function decode(string $base64Cipher): string
        {
            $cipher = base64_decode($base64Cipher);
            if (!is_string($cipher)) {
                throw new CryptoError("");
            }

            $output = "";
            $decryptProcess = openssl_private_decrypt(
                $cipher,
                $output,
                $this->getKey()
            );
            if (!$decryptProcess) {
                throw new CryptoError("");
            }
            return $output;
        }
    }