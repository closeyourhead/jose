<?php
namespace Cyh\Jose\Tests;

use Cyh\Jose\Jwt;
use Cyh\Jose\Utils\Base64Url;
use Cyh\Jose\Utils\Json;
use Cyh\Jose\Signing\Signer\None;
use Cyh\Jose\Signing\Signer\HS256;
use Cyh\Jose\Signing\Signer\HS384;
use Cyh\Jose\Signing\Signer\HS512;
use Cyh\Jose\Signing\Signer\RS256;
use Cyh\Jose\Signing\Signer\RS384;
use Cyh\Jose\Signing\Signer\RS512;
use Cyh\Jose\Signing\Signer\ES256;
use Cyh\Jose\Signing\Signer\ES384;
use Cyh\Jose\Signing\Signer\ES512;
use Cyh\Jose\Validate\Before;
use Cyh\Jose\Validate\Expiration;
use Cyh\Jose\Validate\Issuer;
use Cyh\Jose\Validate\Audience;
use Cyh\Jose\Exception\UnexpectedValueException;
use Cyh\Jose\Exception\MalformedException;
use Cyh\Jose\Signing\Exception\InvalidSignatureException;
use Cyh\Jose\Signing\Exception\UnexpectedValueException as SignerUnexpectedValueException;
use Cyh\Jose\Validate\Exception\BeforeException;
use Cyh\Jose\Validate\Exception\ExpiredException;
use Cyh\Jose\Validate\Exception\InvalidAudienceException;
use Cyh\Jose\Validate\Exception\InvalidIssuerException;
use Cyh\Jose\Validate\Exception\ValidateException;


class JwtTest extends \PHPUnit_Framework_TestCase
{
    private $rsa_prv_key;
    private $rsa_pub_key;

    private $rsa_prv_pem_str;
    private $rsa_pub_pem_str;

    private $ec_prv_pem_str;
    private $ec_pub_pem_str;

    private $ec_prv_key;
    private $ec_pub_key;

    private $valid_claims;
    private $expired_claims;
    private $before_claims;

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

        $now = time();
        $this->valid_claims = array(
            'iat' => $now,
            'iss' => 'www.example.com',
            'aud' => 'test_aud',
            'exp' => ($now + 3600),
            'nbf' => ($now - 1)
        );
        $this->expired_claims = array(
            'exp' => ($now - 3600),
        );
        $this->before_claims = array(
            'nbf' => ($now + 100),
        );
    }

    public function testAlgNoneSuccess()
    {
        $token_strings = Jwt::sign(new None(), $this->valid_claims);

        $validators = array(
            new Expiration(),
            new Before(),
            new Issuer('www.example.com'),
            new Audience('test_aud')
        );

        $verified_claims = Jwt::verify(new None(), $token_strings, null, $validators);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testHS256Success()
    {
        $token_strings = Jwt::sign(new HS256(), $this->valid_claims, 'secret_key');

        $validators = array(
            new Expiration(),
            new Before(),
            new Issuer('www.example.com'),
            new Audience('test_aud')
        );

        $verified_claims = Jwt::verify(new HS256(), $token_strings, 'secret_key', $validators);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testHS384Success()
    {
        $token_strings = Jwt::sign(new HS384(), $this->valid_claims, 'secret_key');
        $verified_claims = Jwt::verify(new HS384(), $token_strings, 'secret_key');

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testHS512Success()
    {
        $token_strings = Jwt::sign(new HS512(), $this->valid_claims, 'secret_key');
        $verified_claims = Jwt::verify(new HS512(), $token_strings, 'secret_key');

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testRS256Success()
    {
        $token_strings = Jwt::sign(new RS256(), $this->valid_claims, $this->rsa_prv_key);
        $verified_claims = Jwt::verify(new RS256(), $token_strings, $this->rsa_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testRS384Success()
    {
        $token_strings = Jwt::sign(new RS384(), $this->valid_claims, $this->rsa_prv_key);
        $verified_claims = Jwt::verify(new RS384(), $token_strings, $this->rsa_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testRS512Success()
    {
        $token_strings = Jwt::sign(new RS512(), $this->valid_claims, $this->rsa_prv_key);
        $verified_claims = Jwt::verify(new RS512(), $token_strings, $this->rsa_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testES256Success()
    {
        $token_strings = Jwt::sign(new ES256(), $this->valid_claims, $this->ec_prv_key);
        $verified_claims = Jwt::verify(new ES256(), $token_strings, $this->ec_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testES384Success()
    {
        $token_strings = Jwt::sign(new ES384(), $this->valid_claims, $this->ec_prv_key);
        $verified_claims = Jwt::verify(new ES384(), $token_strings, $this->ec_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testES512Success()
    {
        $token_strings = Jwt::sign(new ES512(), $this->valid_claims, $this->ec_prv_key);
        $verified_claims = Jwt::verify(new ES512(), $token_strings, $this->ec_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    /**
     * @expectedException ExpiredException
     */
    public function testRS256Expired()
    {
        $token_strings = Jwt::sign(new RS256(), $this->expired_claims, $this->rsa_prv_key);
        Jwt::verify(new RS256(), $token_strings, $this->rsa_pub_key, array(new Expiration()));
    }

    /**
     * @expectedException ExpiredException
     */
    public function testRS256ExpiredDeterminedDateTime()
    {
        $token_strings = Jwt::sign(new RS256(), $this->expired_claims, $this->rsa_prv_key);
        Jwt::verify(new RS256(), $token_strings, $this->rsa_pub_key, array(new Expiration(new \DateTime('now'))));
    }

    /**
     * @expectedException BeforeException
     */
    public function testRS256Before()
    {
        $token_strings = Jwt::sign(new RS256(), $this->expired_claims, $this->rsa_prv_key);
        Jwt::verify(new RS256(), $token_strings, $this->rsa_pub_key, array(new Before()));
    }

    /**
     * @expectedException BeforeException
     */
    public function testRS256BeforeDeterminedDateTime()
    {
        $token_strings = Jwt::sign(new RS256(), $this->expired_claims, $this->rsa_prv_key);
        Jwt::verify(new RS256(), $token_strings, $this->rsa_pub_key, array(new Before(new \DateTime('now'))));
    }

    /**
     * @expectedException InvalidIssuerException
     */
    public function testRS256InvalidIssuer()
    {
        $token_strings = Jwt::sign(new RS256(), $this->expired_claims, $this->rsa_prv_key);
        Jwt::verify(new RS256(), $token_strings, $this->rsa_pub_key, array(new Issuer('example.com')));
    }

    /**
     * @expectedException InvalidAudienceException
     */
    public function testRS256InvalidAudience()
    {
        $token_strings = Jwt::sign(new RS256(), $this->expired_claims, $this->rsa_prv_key);
        Jwt::verify(new RS256(), $token_strings, $this->rsa_pub_key, array(new Audience('invalid_audience')));
    }

    /**
     * @expectedException InvalidSignatureException
     */
    public function testRS256SignatureModified()
    {
        $token_strings = Jwt::sign(new RS256(), $this->expired_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $mod_token = "$h.$p." . Base64Url::encode('invalid_signature');

        Jwt::verify(new RS256(), $mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException InvalidSignatureException
     */
    public function testHS256SignatureModified()
    {
        $token_strings = Jwt::sign(new HS256(), $this->expired_claims, 'secret_key');

        list($h, $p, $s) = explode('.', $token_strings);
        $mod_token = "$h.$p." . Base64Url::encode('invalid_signature');

        Jwt::verify(new HS256(), $mod_token, 'secret_key');
    }

    /**
     * @expectedException InvalidSignatureException
     */
    public function testES256SignatureModified()
    {
        $token_strings = Jwt::sign(new ES256(), $this->expired_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $mod_token = "$h.$p." . Base64Url::encode('invalid_signature');

        Jwt::verify(new ES256(), $mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testRS256NoMatchPrivateKeyType()
    {
        Jwt::sign(new RS256(), $this->valid_claims, $this->ec_prv_key);
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testRS256NoMatchPublicKeyType()
    {
        $token_strings = Jwt::sign(new RS256(), $this->valid_claims, $this->rsa_prv_key);
        Jwt::verify(new RS256(), $token_strings, $this->ec_pub_key);
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testES256NoMatchPrivateKeyType()
    {
        $jwt = new Jwt(new ES256());
        $jwt->sign($this->valid_claims, $this->rsa_prv_key);
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testES256NoMatchPublicKeyType()
    {
        $token_strings = Jwt::sign(new ES256(), $this->valid_claims, $this->ec_prv_key);
        Jwt::verify(new ES256(), $token_strings, $this->rsa_pub_key);
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testRS256InvalidPrivateKey()
    {
        Jwt::sign(new RS256(), $this->valid_claims, 'invalid_prv_key');
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testRS256InvalidPublicKey()
    {
        $token_strings = Jwt::sign(new RS256(), $this->valid_claims, $this->rsa_prv_key);
        Jwt::verify(new RS256(), $token_strings, 'invalid_pub_key');
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testHS256InvalidSecretKey()
    {
        $token_strings = Jwt::sign(new HS256(), $this->valid_claims, 'secret_key');
        Jwt::verify(new HS256(), $token_strings, 'invalid_secret_key');
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testRS256ModifiedHeaderTyp()
    {
        $token_strings = Jwt::sign(new RS256(), $this->valid_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $header = Json::decode(Base64Url::decode($h));
        $header['typ'] = 'JOKE';
        $h = Base64Url::encode(Json::encode($header));
        $mod_token = "$h.$p.$s";

        Jwt::verify(new RS256(), $mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException MalformedException
     */
    public function testRS256ModifiedAlgHeaderNone()
    {
        $token_strings = Jwt::sign(new RS256(), $this->valid_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $header = Json::decode(Base64Url::decode($h));
        $header['alg'] = 'none';
        $h = Base64Url::encode(Json::encode($header));
        $mod_token = "$h.$p.$s";

        Jwt::verify(new RS256(), $mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException MalformedException
     */
    public function testRS256ModifiedAlgHeaderNoMatch()
    {
        $token_strings = Jwt::sign(new RS256(), $this->valid_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $header = Json::decode(Base64Url::decode($h));
        $header['alg'] = 'HS256';
        $h = Base64Url::encode(Json::encode($header));
        $mod_token = "$h.$p.$s";

        Jwt::verify(new RS256(), $mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException InvalidSignatureException
     */
    public function testRS256ModifiedClaimExp()
    {
        $token_strings = Jwt::sign(new RS256(), $this->valid_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $payload = Json::decode(Base64Url::decode($p));
        $payload['exp'] = (time() + 86400);
        $p = Base64Url::encode(Json::encode($payload));
        $mod_token = "$h.$p.$s";

        Jwt::verify(new RS256(), $mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException MalformedException
     */
    public function testRS256MalformedToken()
    {
        Jwt::verify(new RS256(), 'malformed_token_strings', $this->rsa_pub_key);
    }



    public function testRS256KeyIsPemStrSuccess()
    {
        $token_strings = Jwt::sign(new RS256(), $this->valid_claims, $this->rsa_prv_pem_str, 'password');
        $verified_claims = Jwt::verify(new RS256(), $token_strings, $this->rsa_pub_pem_str);
        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testES256KeyIsPemStrSuccess()
    {
        $token_strings = Jwt::sign(new ES256(), $this->valid_claims, $this->ec_prv_pem_str);
        $verified_claims = Jwt::verify(new ES256(), $token_strings, $this->ec_pub_pem_str);
        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testRS256PrivateKeyIsPemStrInvalidKeyType()
    {
        Jwt::sign(new RS256(), $this->valid_claims, $this->ec_prv_pem_str);
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testRS256PublicKeyIsPemStrInvalidKeyType()
    {
        $token_strings = Jwt::sign(new RS256(), $this->valid_claims, $this->rsa_prv_pem_str);
        Jwt::verify(new RS256(), $token_strings, $this->ec_pub_pem_str);
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testES256PrivateKeyIsPemStrInvalidKeyType()
    {
        Jwt::sign($this->valid_claims, $this->rsa_prv_pem_str);
    }

    /**
     * @expectedException SignerUnexpectedValueException
     */
    public function testES256PublicKeyIsPemStrInvalidKeyType()
    {
        $token_strings = Jwt::sign(new ES256(), $this->valid_claims, $this->ec_prv_pem_str);
        Jwt::verify(new ES256(), $token_strings, $this->rsa_pub_pem_str);
    }
}
