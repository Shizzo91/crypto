<?php

    namespace Crypto\Symmetrical;

    use Crypto\Helper\AbstractCrypto;
    use Crypto\Helper\CryptoException;

    class SymmetricalCrypto extends AbstractCrypto
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
         * @throws \Exception
         */
        public function encode(string $data): string
        {
            $iv = random_bytes(16);
            $encryptedRaw = openssl_encrypt(
                (string) $data,
                "AES-256-CBC",
                $this->hashedPassword,
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($encryptedRaw === false) {
                throw new CryptoException("encoding failed", 301);
            }

            return $iv.$encryptedRaw;
        }

        /**
         * @inheritDoc
         * @throws CryptoException
         */
        public function decode(string $cipher): string
        {
            $iv = substr($cipher,0,16);
            $encrypted = substr($cipher,16);
            $decrypt = openssl_decrypt(
                $encrypted,
                "AES-256-CBC",
                $this->hashedPassword,
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($decrypt === false) {
                throw new CryptoException("decode failed", 302);
            }

            return $decrypt;
        }
    }