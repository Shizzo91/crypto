<?php

    namespace Crypto\Symmetrical;

    use Crypto\Helper\CryptoException;
    use Crypto\Helper\CryptoInterface;

    class SymmetricalCrypto implements CryptoInterface
    {

        protected $hashedPassword;
        public function __construct(
            string $password
        ){
            $this->hashedPassword = hash('sha256', $password);
        }

        /**
         * @inheritDoc
         * @throws CryptoException
         */
        public function encode(string $data): string
        {
            $iv = random_bytes(16);
            $encryptedRaw = openssl_encrypt(
                (string) $data,
                "AES-256-CBC",
                $this->hashedPassword,
                0,
                $iv
            );

            if ($encryptedRaw === false) {
                throw new CryptoException("", 301);
            }

            $encryptedRawCombine = $iv.base64_decode($encryptedRaw);

            return base64_encode($encryptedRawCombine);
        }

        /**
         * @inheritDoc
         * @throws CryptoException
         */
        public function decode(string $base64Cipher): string
        {
            $cipher = base64_decode($base64Cipher);
            $iv = substr($cipher,0,16);
            $encrypted = base64_encode(substr($cipher,16));
            $decrypt = openssl_decrypt(
                $encrypted,
                "AES-256-CBC",
                $this->hashedPassword,
                0,
                $iv
            );

            if ($decrypt === false) {
                throw new CryptoException("", 302);
            }

            return $decrypt;
        }
    }