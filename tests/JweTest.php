<?php

use Cyh\Jose\Jwe;
use Cyh\Jose\Encryption\Alg\RSA1_5;
use Cyh\Jose\Encryption\Alg\RSA_OAEP;
use Cyh\Jose\Encryption\Enc\A128CBC_HS256;
use Cyh\Jose\Encryption\Enc\A256CBC_HS512;

class JweTest extends PHPUnit_Framework_TestCase
{
    private $rsa_prv_key;
    private $rsa_pub_key;

    private $rsa_prv_pem_str;
    private $rsa_pub_pem_str;

    private $ec_prv_pem_str;
    private $ec_pub_pem_str;

    private $ec_prv_key;
    private $ec_pub_key;

    public function setUp()
    {
        $this->rsa_prv_key = openssl_get_privatekey(
            'file://' . dirname(__FILE__) . '/keys/rsa_aes256_2048_private.pem',
            'password'
        );
        $this->rsa_pub_key = openssl_get_publickey('file://' . dirname(__FILE__) . '/keys/rsa_aes256_2048_public.pem');

        $this->rsa_prv_pem_str = file_get_contents(dirname(__FILE__) . '/keys/rsa_aes256_2048_private.pem');
        $this->rsa_pub_pem_str = file_get_contents(dirname(__FILE__) . '/keys/rsa_aes256_2048_public.pem');

        $this->ec_prv_key = openssl_get_privatekey('file://' . dirname(__FILE__) . '/keys/ec_prime256v1_private.pem');
        $this->ec_pub_key = openssl_get_publickey('file://' . dirname(__FILE__) . '/keys/ec_prime256v1_public.pem');

        $this->ec_prv_pem_str = file_get_contents(dirname(__FILE__) . '/keys/ec_prime256v1_private.pem');
        $this->ec_pub_pem_str = file_get_contents(dirname(__FILE__) . '/keys/ec_prime256v1_public.pem');
    }

    public function testRSA1_5_A128CBC_HS256Success()
    {
        $base_str = 'hello world!';

        $encrypted = Jwe::encrypt(new RSA1_5(), new A128CBC_HS256(), $base_str, $this->rsa_pub_key);
        $decrypted = Jwe::decrypt(new RSA1_5(), new A128CBC_HS256(), $encrypted, $this->rsa_prv_key);

        $this->assertEquals($base_str, $decrypted);
    }

    public function testRSA1_5_A256CBC_HS512Success()
    {
        $base_str = 'hello world!';

        $encrypted = Jwe::encrypt(new RSA1_5(), new A256CBC_HS512(), $base_str, $this->rsa_pub_key);
        $decrypted = Jwe::decrypt(new RSA1_5(), new A256CBC_HS512(), $encrypted, $this->rsa_prv_key);

        $this->assertEquals($base_str, $decrypted);
    }

    public function testRSA_OAEP_A128CBC_HS256Success()
    {
        $base_str = 'hello world!';

        $encrypted = Jwe::encrypt(new RSA_OAEP(), new A128CBC_HS256(), $base_str, $this->rsa_pub_key);
        $decrypted = Jwe::decrypt(new RSA_OAEP(), new A128CBC_HS256(), $encrypted, $this->rsa_prv_key);

        $this->assertEquals($base_str, $decrypted);
    }

    public function testRSA_OAEP_A256CBC_HS512Success()
    {
        $base_str = 'hello world!';

        $encrypted = Jwe::encrypt(new RSA_OAEP(), new A256CBC_HS512(), $base_str, $this->rsa_pub_key);
        $decrypted = Jwe::decrypt(new RSA_OAEP(), new A256CBC_HS512(), $encrypted, $this->rsa_prv_key);

        $this->assertEquals($base_str, $decrypted);
    }
}
