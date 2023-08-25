# PASERK Wrapper for AWS KMS

[![Build Status](https://github.com/paragonie/paserk-php-wrap-aws-kms/actions/workflows/ci.yml/badge.svg)](https://github.com/paragonie/paserk-php/actions)
[![Latest Stable Version](https://poser.pugx.org/paragonie/paserk-wrap-aws-kms/v/stable)](https://packagist.org/packages/paragonie/paserk-wrap-aws-kms)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/paserk-wrap-aws-kms/v/unstable)](https://packagist.org/packages/paragonie/paserk-wrap-aws-kms)
[![License](https://poser.pugx.org/paragonie/paserk-wrap-aws-kms/license)](https://packagist.org/packages/paragonie/paserk-wrap-aws-kms)
[![Downloads](https://img.shields.io/packagist/dt/paragonie/paserk-wrap-aws-kms.svg)](https://packagist.org/packages/paragonie/paserk-wrap-aws-kms)

Integrates PASERK with AWS KMS for key-wrapping. **Requires PHP 8.1 or newer.**

This repository is an extension of [PASERK for PHP](https://github.com/paragonie/paserk-php).

## PASERK Specification

The PASERK Specification can be found [in this repository](https://github.com/paseto-standard/paserk).

## Installing

```terminal
composer require paragonie/paserk-aws-kms
```

## Usage

### Initialization

You will need a [`KmsClient`](https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.Kms.KmsClient.html) object and
a PASETO protocol version object.

```php
<?php
use Aws\Kms\KmsClient;
use ParagonIE\Paseto\ProtocolInterface;
use ParagonIE\Paserk\Operations\Wrap\AwsKms;

/** 
 * @var KmsClient $kmsClient
 * @var ProtocolInterface $pasetoProtocol
 */

$awsKmsWrapper = new AwsKms($kmsClient, $pasetoProtocol);
```

If you'd like to specify custom [Encryption Context](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context):

```php
$awsKmsWrapper->setEncryptionContex([
    'department' => '10103.0'
]);
```

You can then pass the `AwsKms` object to the constructor of the PASERK `Wrap` Operation class.

```php
/**
 * @var AwsKms $awsKmsWrapper
 */ 
$wrapper = new \ParagonIE\Paserk\Operations\Wrap($awsKmsWrapper);
```

See [the paserk-php documentation](https://github.com/paragonie/paserk-php/tree/master/docs/Wrap) for further details.
