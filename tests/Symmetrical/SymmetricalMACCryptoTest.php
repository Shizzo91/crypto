<?php

    namespace Crypto\Test\Symmetrical;

    use Crypto\Symmetrical\SymmetricalMACCrypto;
    use PHPUnit\Framework\TestCase;

    class SymmetricalMACCryptoTest extends TestCase
    {

        public static function generateRandomString($length = 10): string
        {
            $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $charactersLength = strlen($characters);
            $randomString = '';
            for ($i = 0; $i < $length; $i++) {
                $randomString .= $characters[random_int(0, $charactersLength - 1)];
            }
            return $randomString;
        }

        /**
         * @dataProvider dataProvider
         */
        public function testEncode(string $value, int $length): void
        {
            $crypto = new SymmetricalMACCrypto($length);
            self::assertIsString($crypto->encodeAsBase64($value));
        }

        /**
         * @dataProvider dataProvider
         */
        public function testEncodeString(string $value, int $length): void
        {
            $crypto = new SymmetricalMACCrypto($length);
            self::assertMatchesRegularExpression("/[-A-Za-z0-9+\/=]+/", $crypto->encodeAsBase64($value));
        }

        /**
         * @dataProvider dataProvider
         */
        public function testEncodeGzipString(string $value, int $length): void
        {
            $crypto = new SymmetricalMACCrypto($length);
            self::assertMatchesRegularExpression("/[-A-Za-z0-9+\/=]+/", $crypto->encodeAsGzipBase64($value));
        }

        /**
         * @dataProvider dataProvider
         */
        public function testDecode(string $value, int $length): void
        {
            $crypto = new SymmetricalMACCrypto($length);
            $encoded = $crypto->encode($value);
            self::assertSame($value, $crypto->decode($encoded));
        }

        /**
         * @dataProvider dataProvider
         */
        public function testDecodeBase64(string $value, int $length): void
        {
            $crypto = new SymmetricalMACCrypto($length);
            $encoded = $crypto->encodeAsBase64($value);
            self::assertSame($value, $crypto->decodeFromBase64($encoded));
        }

        /**
         * @dataProvider dataProvider
         */
        public function testDecodeGzip(string $value, int $length): void
        {
            $crypto = new SymmetricalMACCrypto($length);
            $encoded = $crypto->encodeAsGzip($value);
            self::assertSame($value, $crypto->decodeFromGzip($encoded));
        }

        /**
         * @dataProvider dataProvider
         */
        public function testDecodeGzipBase64(string $value, int $length): void
        {
            $crypto = new SymmetricalMACCrypto($length);
            $encoded = $crypto->encodeAsGzipBase64($value);
            self::assertSame($value, $crypto->decodeFromGzipBase64($encoded));
        }

        public static function dataProviderRaw(): \Generator
        {
            try {
                $length = random_int(10, 25);
            } catch (\Exception $e) {
                $length = 22;
            }

            $lengthArray = array_map(function ($v) {
                return 2 ** (5 + $v);
            }, range(1, 5));
            foreach ($lengthArray AS $length) {
                for ($i = 0; $i < $length; $i++) {
                    try {
                        $value = self::generateRandomString(random_int(10, 55));
                    } catch (\Exception $e) {
                        $value = self::generateRandomString(30);
                    }
                    yield "index-{$i}-{$length}-bytes" => [$value, $length];
                }
            }
        }

        public static function dataProvider(): array
        {
            return iterator_to_array(self::dataProviderRaw());
        }
    }
