<?php

    namespace Crypto\Hybrid;

    use Crypto\Asymmetric\DoubleCrypto;
    use Crypto\Asymmetric\PrivateSimpleCrypto;
    use Crypto\Asymmetric\PublicSimpleCrypto;
    use Crypto\Helper\CryptoException;
    use Crypto\Helper\CryptoInterface;
    use Crypto\Helper\CryptoTrait;
    use Crypto\Symmetrical\SymmetricalCrypto;

    class HybridCrypto implements CryptoInterface
    {
        use CryptoTrait;
        protected $asymmetricCrypto;
        protected $symmetricalCrypto;



        /**
         * @param string $password
         * @param PublicSimpleCrypto|PrivateSimpleCrypto|DoubleCrypto $asymmetricCrypto
         * @return self
         */
        public static function create(
            string $password,
            $asymmetricCrypto
        ): HybridCrypto
        {
            $crypto = new SymmetricalCrypto($password);
            return new self($asymmetricCrypto, $crypto);
        }

        /**
         * @param string $password
         * @param string $publicKey
         * @return HybridCrypto
         * @throws CryptoException
         */
        public static function createPublicSimple(
            string $password,
            string $publicKey
        ): HybridCrypto
        {
            $publicSimpleCrypto = new PublicSimpleCrypto($publicKey);
            return self::create($password, $publicSimpleCrypto);
        }

        /**
         * @param string $password
         * @param string $privateKey
         * @param string|null $passphrase
         * @return HybridCrypto
         * @throws CryptoException
         */
        public static function createPrivateSimple(
            string $password,
            string $privateKey,
            ?string $passphrase = null
        ): HybridCrypto
        {
            $privateSimpleCrypto = new PrivateSimpleCrypto($privateKey, $passphrase);
            return self::create($password, $privateSimpleCrypto);
        }

        /**
         * @param string $password
         * @param string $publicKey
         * @param string $privateKey
         * @param string|null $passphrase
         * @return HybridCrypto
         * @throws CryptoException
         */
        public static function createDouble(
            string $password,
            string $publicKey,
            string $privateKey,
            ?string $passphrase = null
        ): HybridCrypto
        {
            $doubleCrypto = DoubleCrypto::create($publicKey, $privateKey, $passphrase);
            return self::create($password, $doubleCrypto);
        }

        /**
         * @param PublicSimpleCrypto|PrivateSimpleCrypto|DoubleCrypto $asymmetricCrypto
         * @param SymmetricalCrypto $symmetricalCrypto
         */
        public function __construct(
            $asymmetricCrypto,
            SymmetricalCrypto $symmetricalCrypto
        ){
            $this->symmetricalCrypto = $symmetricalCrypto;
            $this->asymmetricCrypto = $asymmetricCrypto;
        }

        /**
         * @inheritDoc
         * @throws CryptoException
         */
        public function encode(string $data): string
        {
            $symmetricalEncodedData = $this->symmetricalCrypto->encode($data);
            return $this->asymmetricCrypto->encode($symmetricalEncodedData);
        }

        /**
         * @inheritDoc
         * @throws CryptoException
         */
        public function decode(string $cipher): string
        {
            $asymmetricDecoded = $this->asymmetricCrypto->decode($cipher);
            return $this->symmetricalCrypto->decode($asymmetricDecoded);
        }
    }