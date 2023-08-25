<?php
declare(strict_types=1);
namespace ParagonIE\Paserk\Operations\Wrap\Tests;

use Aws\Kms\KmsClient;
use Exception;
use ParagonIE\Certainty\RemoteFetch;
use ParagonIE\ConstantTime\Hex;
use ParagonIE\Paserk\Operations\{
    Wrap,
    Wrap\AwsKms
};
use ParagonIE\Paserk\PaserkException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\{
    AsymmetricSecretKey,
    Base\SymmetricKey as BaseSymmetricKey,
    Base\AsymmetricSecretKey as BaseAsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\Paseto\Protocol\{
    Version3,
    Version4
};
use ParagonIE\Paseto\ProtocolInterface;
use PHPUnit\Framework\TestCase;
use TypeError;

/**
 * @covers KmsKey
 */
class AwsKmsTest extends TestCase
{
    public function getAwsKms(ProtocolInterface $protocol): AwsKms
    {
        $remoteFetch = new RemoteFetch(dirname(__DIR__) . '/data');
        $latestBundle = $remoteFetch->getLatestBundle()->getFilePath();

        // Allow local credentials to be provided for local dev/testing
        $jsonFile = dirname(__DIR__) . '/data/kms.json';
        if (is_readable($jsonFile)) {
            $config = json_decode(file_get_contents($jsonFile), true);
        } else {
            $config = [
                'key-id' => 'b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
                'key-arn' => 'arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f',
                'region' => 'us-west-2'
            ];
        }

        $kmsClient = new KmsClient([
            'profile' => 'default',
            'region' => $config['region'],
            'http'    => ['verify' => $latestBundle]
        ]);
        return new AwsKms(
            $kmsClient,
            $protocol,
            $config['key-arn']
        );
    }

    /**
     * @throws PasetoException
     * @throws Exception
     */
    public function wrapProvider(): array
    {
        return [
            [new SymmetricKey(str_repeat("\x31", 32), new Version3)],
            [new SymmetricKey(str_repeat("\x31", 32), new Version4)],
            [new SymmetricKey(str_repeat("\x42", 32), new Version3)],
            [new SymmetricKey(str_repeat("\x42", 32), new Version4)],
            [SymmetricKey::generate(new Version3)],
            [SymmetricKey::generate(new Version4)],
            [AsymmetricSecretKey::newVersionKey(str_repeat("\x31", 48), new Version3)],
            [AsymmetricSecretKey::newVersionKey(str_repeat("\x31", 32), new Version4)],
            [AsymmetricSecretKey::newVersionKey(str_repeat("\x42", 48), new Version3)],
            [AsymmetricSecretKey::newVersionKey(str_repeat("\x42", 32), new Version4)],
            [AsymmetricSecretKey::generate(new Version3)],
            [AsymmetricSecretKey::generate(new Version4)],
        ];
    }

    /**
     * @dataProvider wrapProvider
     */
    public function testWrapUnwrap(BaseSymmetricKey|AsymmetricSecretKey $key)
    {
        $wrapper = new Wrap($this->getAwsKms($key->getProtocol()));
        if ($key instanceof BaseSymmetricKey) {
            $this->doSymmetricWrapUnwrap($wrapper, $key);
        } else {
            $this->doAsymmetricWrapUnwrap($wrapper, $key);
        }
    }

    private function doAsymmetricWrapUnwrap(Wrap $wrapper, AsymmetricSecretKey $key): void
    {
        $wrapped = $wrapper->secretWrap($key);
        $unwrap = $wrapper->secretUnwrap($wrapped);
        $this->assertSame(
            Hex::encode($key->getPublicKey()->raw()),
            Hex::encode($unwrap->getPublicKey()->raw()),
            'Different keys returned from unwrapping'
        );
    }

    private function doSymmetricWrapUnwrap(Wrap $wrapper, BaseSymmetricKey $key): void
    {
        $wrapped = $wrapper->localWrap($key);
        $unwrap = $wrapper->localUnwrap($wrapped);
        $this->assertSame(
            Hex::encode($key->raw()),
            Hex::encode($unwrap->raw()),
            'Different keys returned from unwrapping'
        );
    }

    /**
     * @dataProvider wrapProvider
     */
    public function tesAlgorithmLucidityKms(SymmetricKey|AsymmetricSecretKey $key): void
    {
        $wrapper = $this->getAwsKms($this->getWrongProtocol($key->getProtocol()));
        if ($key instanceof BaseSymmetricKey) {
            $header = $key->getProtocol() . '.local.';
        } elseif ($key instanceof BaseAsymmetricSecretKey) {
            $header = $key->getProtocol() . '.public.';
        } else {
            throw new TypeError();
        }
        $this->expectException('error');
        $wrapper->wrapKey($header, $key);
    }

    public function tesAlgorithmLucidityHeader(SymmetricKey|AsymmetricSecretKey $key): void
    {
        $wrapper = $this->getAwsKms($key->getProtocol());
        if ($key instanceof BaseSymmetricKey) {
            $header = $key->getProtocol() . '.public.';
        } elseif ($key instanceof BaseAsymmetricSecretKey) {
            $header = $key->getProtocol() . '.local.';
        } else {
            throw new TypeError();
        }
        $this->expectExceptionObject(new PaserkException('test'));
        $wrapper->wrapKey($header, $key);
    }

    /**
     * @param ProtocolInterface $protocol
     * @return ProtocolInterface
     * @throws Exception
     */
    private function getWrongProtocol(ProtocolInterface $protocol): ProtocolInterface
    {
        if ($protocol instanceof Version3) {
            return new Version4;
        }
        if ($protocol instanceof Version4) {
            return new Version3;
        }
        throw new Exception('Unknown type');
    }
}
