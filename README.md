# JWT/JWS/JWE library for PHP

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/closeyourhead/jose/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/closeyourhead/jose/?branch=master)
[![Coverage Status](https://coveralls.io/repos/closeyourhead/jose/badge.svg?branch=master&service=github)](https://coveralls.io/github/closeyourhead/jose?branch=master)
[![SensioLabsInsight](https://insight.sensiolabs.com/projects/8bc06326-2fce-4399-8c42-b8204982fe7d/big.png)](https://insight.sensiolabs.com/projects/8bc06326-2fce-4399-8c42-b8204982fe7d)

## Requirements

php version >= 5.4.8

php-json extension

php-hash extension

php-openssl extension

php-mbstring extension

## Provided features

*signing/verifying

*encryption/decryption

*claims validation(optional)

if you need, you can use a claim set validator at verifying.

you can add another validator that you have created.

it's must implement the Cyh\Jose\Validate\ValidateInterface.

*already exp, nbf, iss, aud validator.

## Supported algorithms

JWS signing: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512

JWE key encryption: RSA1_5, RSA-OAEP

JWE content encryption: A128CBC-HS256, A256CBC-HS512

## Usage
```php
<?php
require_once './vendor/autoload.php';

use Cyh\Jose\Jwt;
use Cyh\Jose\Signing\Signer\HS256;
use Cyh\Jose\Validate\Expiration;
use Cyh\Jose\Signing\Exception\InvalidSignatureException;
use Cyh\Jose\Validate\Exception\ExpiredException;
use Cyh\Jose\Jwe;
use Cyh\Jose\Encryption\Alg\RSA_OAEP;
use Cyh\Jose\Encryption\Enc\A128CBC_HS256;


// sign
$claims = array(
    'sub' => 'iamsubject',
    'exp' => (time() + 3600),
);
$secret_key = hash('sha256', 'secret_key');
$token_strings = Jwt::sign(new HS256(), $claims, $secret_key);

// verify
try {
    $verified_claims = Jwt::verify(
        new HS256(),
        $token_strings,
        $secret_key,
        array(new Expiration())
    );

    var_dump($verified_claims);

} catch (InvalidSignatureException $e) {
    // ...

} catch (ExpiredException $e) {
    // ...

} catch (\Exception $e) {
    // ...
}


// encrypt
$rsa_pub_key = 'file://' . dirname(__FILE__) . '/tests/keys/rsa_aes256_2048_public.pem';
$content = 'i am plain text content';
$encrypted = Jwe::encrypt(
    new RSA_OAEP(),
    new A128CBC_HS256(),
    $content,
    $rsa_pub_key
);

// decrypt
$rsa_prv_key = 'file://' . dirname(__FILE__) . '/tests/keys/rsa_aes256_2048_private.pem';
$decrypted = Jwe::decrypt(
    new RSA_OAEP(),
    new A128CBC_HS256(),
    $encrypted,
    $rsa_prv_key,
    'password'
);

var_dump($decrypted);
