<?php

    namespace Crypto\Helper;

    interface CryptoInterface
    {
        const ENCRYPT_BLOCK_SIZE = 200;
        const DECRYPT_BLOCK_SIZE = 256;

        /**
         * define the encode function
         * @param string $data
         * @return string
         */
        public function encode(string $data): string;

        /**
         * define the decode function
         * @param string $base64Cipher
         * @return string
         */
        public function decode(string $base64Cipher): string;

    }