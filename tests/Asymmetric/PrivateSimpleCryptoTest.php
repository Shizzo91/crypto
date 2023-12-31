<?php

    namespace Crypto\Test\Asymmetric;

    use Crypto\Helper\CryptoException;
    use Crypto\Asymmetric\PrivateSimpleCrypto;
    use Crypto\Asymmetric\PublicSimpleCrypto;
    use PHPUnit\Framework\TestCase;

    class PrivateSimpleCryptoTest extends TestCase
    {
        public static $privateKey;
        public static $publicKey;
        public static $fakePrivateKey;
        public static $fakePublicKey;
        protected function setUp(): void
        {
            parent::setUp();
            self::$privateKey = dirname(__DIR__, 2)."/private.pem";
            self::$publicKey = dirname(__DIR__, 2)."/public.pem";
            self::$fakePrivateKey = dirname(__DIR__, 2)."/private.pe";
            self::$fakePublicKey = dirname(__DIR__, 2)."/public.pe";
        }

        public function testFileFound(): void
        {
            $private = new PrivateSimpleCrypto(self::$privateKey);
            self::assertInstanceOf(PrivateSimpleCrypto::class, $private);
        }

        public function testFileNotFound(): void
        {
            $privateKey = self::$fakePrivateKey;
            $this->expectExceptionObject(new CryptoException("private key file not found \"{$privateKey}\"", 101));
            $private = new PrivateSimpleCrypto($privateKey);
        }

        /**
         * @dataProvider keyProvider
         */
        public function testEncode(
            string $privateKey,
            ?string $passphrase,
            string $publicKey
        ): void
        {
            $privateCrypto = new PrivateSimpleCrypto($privateKey, $passphrase);
            self::assertIsString($privateCrypto->encodeAsBase64("hallo"));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testEncodeString(
            string $privateKey,
            ?string $passphrase,
            string $publicKey
        ): void
        {
            $privateCrypto = new PrivateSimpleCrypto($privateKey, $passphrase);
            self::assertMatchesRegularExpression("/[-A-Za-z0-9+\/=]+/", $privateCrypto->encodeAsBase64("hallo"));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testDecode(
            string $privateKey,
            ?string $passphrase,
            string $publicKey
        ): void
        {
            $data = "dsfkljsadflsadfsd";
            $privateCrypto = new PrivateSimpleCrypto($privateKey, $passphrase);
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            $encode = $publicCrypto->encode($data);
            self::assertSame($data, $privateCrypto->decode($encode));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testDecodeBase64(
            string $privateKey,
            ?string $passphrase,
            string $publicKey
        ): void
        {
            $data = "dsfkljsadflsadfsd";
            $privateCrypto = new PrivateSimpleCrypto($privateKey, $passphrase);
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            $encode = $publicCrypto->encodeAsBase64($data);
            self::assertSame($data, $privateCrypto->decodeFromBase64($encode));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testDecodeGzip(
            string $privateKey,
            ?string $passphrase,
            string $publicKey
        ): void
        {
            $data = "dsfkljsadflsadfsd";
            $privateCrypto = new PrivateSimpleCrypto($privateKey, $passphrase);
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            $encode = $publicCrypto->encodeAsGzip($data);
            self::assertSame($data, $privateCrypto->decodeFromGzip($encode));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testDecodeGzipBase64(
            string $privateKey,
            ?string $passphrase,
            string $publicKey
        ): void
        {
            $data = "dsfkljsadflsadfsd";
            $privateCrypto = new PrivateSimpleCrypto($privateKey, $passphrase);
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            $encode = $publicCrypto->encodeAsGzipBase64($data);
            self::assertSame($data, $privateCrypto->decodeFromGzipBase64($encode));
        }

        public static function keyProvider(): array
        {
            $private1 = dirname(__DIR__, 2)."/private.pem";
            $public1 = dirname(__DIR__, 2)."/public.pem";
            $private2 = dirname(__DIR__, 2)."/private-2.pem";
            $public2 = dirname(__DIR__, 2)."/public-2.pem";
            $passphrase2 = "hallo";
            return [
                "key" => [
                    $private1,
                    null,
                    $public1
                ],
                "string" => [
                    file_get_contents($private1),
                    null,
                    $public1
                ],
                "key-2" => [
                    $private2,
                    $passphrase2,
                    $public2
                ],
                "string-2" => [
                    file_get_contents($private2),
                    $passphrase2,
                    $public2
                ],
            ];
        }
    }
