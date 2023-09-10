<?php

    namespace Crypto\Helper;

    trait CryptoTrait
    {
        /**
         * @param string $data
         * @return string
         */
        public function encodeAsBase64(string $data): string
        {
            return base64_encode($this->encode($data));
        }


        public function decodeFromBase64(string $base64Cipher): string
        {

            $cipher = base64_decode($base64Cipher);
            if (!is_string($cipher)) {
                throw new CryptoException("fail to encode base64", 2);
            }
            return $this->decode($cipher);
        }

    }