<?php

    namespace Crypto\Helper;

    interface CryptoInterface
    {

        /**
         * define the encode function
         * @param string|\Stringable $data
         * @return string
         */
        public function encode(string|\Stringable $data): string;

        /**
         * define the decode function
         * @param string $base64Cipher
         * @return string
         */
        public function decode(string $base64Cipher): string;

    }