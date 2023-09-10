<?php

    namespace Crypto\Test\Hybrid;

    use Crypto\Hybrid\HybridCrypto;
    use PHPUnit\Framework\TestCase;

    class HybridCryptoTest extends TestCase
    {


        public static function generateRandomString(?int $length = null): string
        {
            if (is_null($length)) {
                try {
                    $length = random_int(10, 100);
                } catch (\Exception $exception) {
                    $length = 10;
                }
            }

            $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $charactersLength = strlen($characters);
            $randomString = '';
            for ($i = 0; $i < $length; $i++) {
                $randomString .= $characters[random_int(0, $charactersLength - 1)];
            }
            return $randomString;
        }

        /**
         * @dataProvider hybridCryptoProvider
         */
        public function testEncode(HybridCrypto $hybridCrypto): void
        {
            $value = self::generateRandomString();
            self::assertIsString($hybridCrypto->encodeAsBase64($value));
        }


        /**
         * @dataProvider hybridCryptoProvider
         */
        public function testEncodeString(HybridCrypto $hybridCrypto): void
        {
            $value = self::generateRandomString();
            self::assertMatchesRegularExpression("/[-A-Za-z0-9+\/=]+/", $hybridCrypto->encodeAsBase64($value));
        }


        public function testDecodeSimple1(): void
        {
            $value = self::generateRandomString();
            try {
                $password = self::generateRandomString(random_int(10, 25));
            } catch (\Exception $e) {
                $password = self::generateRandomString(22);
            }

            $private = dirname(__DIR__, 2)."/private.pem";
            $public = dirname(__DIR__, 2)."/public.pem";
            $passphrase = null;

            $hybridCryptoPrivate = HybridCrypto::createPrivateSimple($password, $private, $passphrase);
            $encoded = $hybridCryptoPrivate->encode($value);
            $hybridCryptoPublic = HybridCrypto::createPublicSimple($password, $public);
            self::assertSame($value, $hybridCryptoPublic->decode($encoded));

        }
        public function testDecodeSimple2(): void
        {
            $value = self::generateRandomString();
            try {
                $password = self::generateRandomString(random_int(10, 25));
            } catch (\Exception $e) {
                $password = self::generateRandomString(22);
            }

            $private = dirname(__DIR__, 2)."/private-2.pem";
            $public = dirname(__DIR__, 2)."/public-2.pem";
            $passphrase = "hallo";

            $hybridCryptoPrivate = HybridCrypto::createPrivateSimple($password, $private, $passphrase);
            $encoded = $hybridCryptoPrivate->encode($value);
            $hybridCryptoPublic = HybridCrypto::createPublicSimple($password, $public);
            self::assertSame($value, $hybridCryptoPublic->decode($encoded));

        }

        public function testDecodeDouble1(): void
        {
            $value = self::generateRandomString();
            try {
                $password = self::generateRandomString(random_int(10, 25));
            } catch (\Exception $e) {
                $password = self::generateRandomString(22);
            }

                $private1 = dirname(__DIR__, 2)."/private.pem";
                $public1 = dirname(__DIR__, 2)."/public.pem";
                $passphrase1 = null;

                $private2 = dirname(__DIR__, 2)."/private-2.pem";
                $public2 = dirname(__DIR__, 2)."/public-2.pem";
                $passphrase2 = "hallo";

                $hybridCryptoDouble1 = HybridCrypto::createDouble($password, $public2, $private1, $passphrase1);
                $hybridCryptoDouble2 = HybridCrypto::createDouble($password, $public1, $private2, $passphrase2);

                $encoded = $hybridCryptoDouble1->encode($value);
                self::assertSame($value, $hybridCryptoDouble2->decode($encoded));
            }
        public function testDecodeDouble2(): void
        {
            $value = self::generateRandomString();
            try {
                $password = self::generateRandomString(random_int(10, 25));
            } catch (\Exception $e) {
                $password = self::generateRandomString(22);
            }

                $private1 = dirname(__DIR__, 2)."/private.pem";
                $public1 = dirname(__DIR__, 2)."/public.pem";
                $passphrase1 = null;

                $private2 = dirname(__DIR__, 2)."/private-2.pem";
                $public2 = dirname(__DIR__, 2)."/public-2.pem";
                $passphrase2 = "hallo";

                $hybridCryptoDouble1 = HybridCrypto::createDouble($password, $public2, $private1, $passphrase1);
                $hybridCryptoDouble2 = HybridCrypto::createDouble($password, $public1, $private2, $passphrase2);

                $encoded = $hybridCryptoDouble2->encode($value);
                self::assertSame($value, $hybridCryptoDouble1->decode($encoded));
            }

        public static function hybridCryptoProvider(): array
        {
            try {
                $password = self::generateRandomString(random_int(10, 25));
            } catch (\Exception $e) {
                $password = self::generateRandomString(22);
            }

            $private1 = dirname(__DIR__, 2)."/private.pem";
            $public1 = dirname(__DIR__, 2)."/public.pem";
            $passphrase1 = null;

            $private2 = dirname(__DIR__, 2)."/private-2.pem";
            $public2 = dirname(__DIR__, 2)."/public-2.pem";
            $passphrase2 = "hallo";

            $hybridCryptoPrivate1 = HybridCrypto::createPrivateSimple($password, $private1, $passphrase1);
            $hybridCryptoPrivate2 = HybridCrypto::createPrivateSimple($password, $private2, $passphrase2);

            $hybridCryptoPublic1 = HybridCrypto::createPublicSimple($password, $public1);
            $hybridCryptoPublic2 = HybridCrypto::createPublicSimple($password, $public2);

            $hybridCryptoDouble1 = HybridCrypto::createDouble($password, $public2, $private1, $passphrase1);
            $hybridCryptoDouble2 = HybridCrypto::createDouble($password, $public1, $private2, $passphrase2);

            return [
                'hybridCryptoPrivate1' => [$hybridCryptoPrivate1],
                'hybridCryptoPrivate2' => [$hybridCryptoPrivate2],
                'hybridCryptoPublic1' => [$hybridCryptoPublic1],
                'hybridCryptoPublic2' => [$hybridCryptoPublic2],
                'hybridCryptoDouble1' => [$hybridCryptoDouble1],
                'hybridCryptoDouble2' => [$hybridCryptoDouble2],
            ];
        }
    }
