<?php

    namespace Crypto\Symmetrical;

    use Crypto\Helper\CryptoTrait;
    use Crypto\Symmetrical\SymmetricalCrypto;

    class SymmetricalMACCrypto extends SymmetricalCrypto
    {
        protected $password;
        protected $length;

        /**
         * @throws \Exception
         */
        public function __construct(int $length)
        {
            $this->length = $length;
            $this->password = random_bytes($this->length);
            parent::__construct($this->password);
        }

        public function encode(string $data): string
        {
            return $this->password.parent::encode($data);
        }

        public function decode(string $cipher): string
        {
            $password = substr($cipher,0, $this->length);
            $encrypted = substr($cipher,$this->length);
            $this->password = $password;
            $this->hashedPassword = hash('sha256', $this->password);
            return parent::decode($encrypted);
        }

    }