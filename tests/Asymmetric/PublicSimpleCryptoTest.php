<?php

    namespace Crypto\Test\Asymmetric;

    use Crypto\Helper\CryptoException;
    use Crypto\Asymmetric\PrivateSimpleCrypto;
    use Crypto\Asymmetric\PublicSimpleCrypto;
    use PHPUnit\Framework\TestCase;

    class PublicSimpleCryptoTest extends TestCase
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
            $publicCrypto = new PublicSimpleCrypto(self::$publicKey);
            self::assertInstanceOf(PublicSimpleCrypto::class, $publicCrypto);
        }

        public function testFileNotFound(): void
        {
            $publicKey = self::$fakePublicKey;
            $this->expectExceptionObject(new CryptoException("public key file not found \"{$publicKey}\"", 201));
            $publicCrypto = new PublicSimpleCrypto($publicKey);
        }

        /**
         * @dataProvider keyProvider
         */
        public function testEncode(string $publicKey): void
        {
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            self::assertIsString($publicCrypto->encodeAsBase64("hallo"));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testEncodeString(string $publicKey): void
        {
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            self::assertMatchesRegularExpression("/[-A-Za-z0-9+\/=]+/", $publicCrypto->encodeAsBase64("hallo"));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testDecode(string $publicKey): void
        {
            $data = "hallo";
            $privateCrypto = new PrivateSimpleCrypto(self::$privateKey);
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            $encode = $privateCrypto->encode($data);
            self::assertSame($data, $publicCrypto->decode($encode));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testDecodeBase64(string $publicKey): void
        {
            $data = "hallo";
            $privateCrypto = new PrivateSimpleCrypto(self::$privateKey);
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            $encode = $privateCrypto->encodeAsBase64($data);
            self::assertSame($data, $publicCrypto->decodeFromBase64($encode));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testDecodeGzip(string $publicKey): void
        {
            $data = "hallo";
            $privateCrypto = new PrivateSimpleCrypto(self::$privateKey);
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            $encode = $privateCrypto->encodeAsGzip($data);
            self::assertSame($data, $publicCrypto->decodeFromGzip($encode));
        }

        /**
         * @dataProvider keyProvider
         */
        public function testDecodeGzipBase64(string $publicKey): void
        {
            $data = "hallo";
            $privateCrypto = new PrivateSimpleCrypto(self::$privateKey);
            $publicCrypto = new PublicSimpleCrypto($publicKey);
            $encode = $privateCrypto->encodeAsGzipBase64($data);
            self::assertSame($data, $publicCrypto->decodeFromGzipBase64($encode));
        }


        public static function keyProvider(): array
        {
            $key = dirname(__DIR__, 2)."/public.pem";
            return [
                "key" => [$key],
                "string" => [file_get_contents($key)]
            ];
        }
    }
