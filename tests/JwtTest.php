<?php

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

class JwtTest extends PHPUnit_Framework_TestCase
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
        $jwt = new Jwt(new None());
        $token_strings = $jwt->sign($this->valid_claims);

        $jwt->addValidator(new Cyh\Jose\Validate\Expiration());
        $jwt->addValidator(new Cyh\Jose\Validate\Before());
        $jwt->addValidator(new Cyh\Jose\Validate\Issuer('www.example.com'));
        $jwt->addValidator(new Cyh\Jose\Validate\Audience('test_aud'));

        $verified_claims = $jwt->verify($token_strings);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testHS256Success()
    {
        $jwt = new Jwt(new HS256());
        $token_strings = $jwt->sign($this->valid_claims, 'secret_key');

        $jwt->addValidator(new Cyh\Jose\Validate\Expiration());
        $jwt->addValidator(new Cyh\Jose\Validate\Before());
        $jwt->addValidator(new Cyh\Jose\Validate\Issuer('www.example.com'));
        $jwt->addValidator(new Cyh\Jose\Validate\Audience('test_aud'));

        $verified_claims = $jwt->verify($token_strings, 'secret_key');

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testHS384Success()
    {
        $jwt = new Jwt(new HS384());
        $token_strings = $jwt->sign($this->valid_claims, 'secret_key');

        $verified_claims = $jwt->verify($token_strings, 'secret_key');

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testHS512Success()
    {
        $jwt = new Jwt(new HS512());
        $token_strings = $jwt->sign($this->valid_claims, 'secret_key');

        $verified_claims = $jwt->verify($token_strings, 'secret_key');

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testRS256Success()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        $verified_claims = $jwt->verify($token_strings, $this->rsa_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testRS384Success()
    {
        $jwt = new Jwt(new RS384());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        $verified_claims = $jwt->verify($token_strings, $this->rsa_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testRS512Success()
    {
        $jwt = new Jwt(new RS512());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        $verified_claims = $jwt->verify($token_strings, $this->rsa_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testES256Success()
    {
        $jwt = new Jwt(new ES256());
        $token_strings = $jwt->sign($this->valid_claims, $this->ec_prv_key);

        $verified_claims = $jwt->verify($token_strings, $this->ec_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testES384Success()
    {
        $jwt = new Jwt(new ES384());
        $token_strings = $jwt->sign($this->valid_claims, $this->ec_prv_key);

        $verified_claims = $jwt->verify($token_strings, $this->ec_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testES512Success()
    {
        $jwt = new Jwt(new ES512());
        $token_strings = $jwt->sign($this->valid_claims, $this->ec_prv_key);

        $verified_claims = $jwt->verify($token_strings, $this->ec_pub_key);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    /**
     * @expectedException Cyh\Jose\Validate\Exception\ExpiredException
     */
    public function testRS256Expired()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->expired_claims, $this->rsa_prv_key);

        $jwt->addValidator(new Cyh\Jose\Validate\Expiration());
        $jwt->verify($token_strings, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Validate\Exception\ExpiredException
     */
    public function testRS256ExpiredDeterminedDateTime()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->expired_claims, $this->rsa_prv_key);

        $jwt->addValidator(new Cyh\Jose\Validate\Expiration(new \DateTime('now')));
        $jwt->verify($token_strings, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Validate\Exception\BeforeException
     */
    public function testRS256Before()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->before_claims, $this->rsa_prv_key);

        $jwt->addValidator(new Cyh\Jose\Validate\Before());
        $jwt->verify($token_strings, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Validate\Exception\BeforeException
     */
    public function testRS256BeforeDeterminedDateTime()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->before_claims, $this->rsa_prv_key);

        $jwt->addValidator(new Cyh\Jose\Validate\Before(new \DateTime('now')));
        $jwt->verify($token_strings, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Validate\Exception\InvalidIssuerException
     */
    public function testRS256InvalidIssuer()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        $jwt->addValidator(new Cyh\Jose\Validate\Issuer('example.com'));
        $jwt->verify($token_strings, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Validate\Exception\InvalidAudienceException
     */
    public function testRS256InvalidAudience()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        $jwt->addValidator(new Cyh\Jose\Validate\Audience('test_invalid_audience'));
        $jwt->verify($token_strings, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\InvalidSignatureException
     */
    public function testRS256SignatureModified()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $mod_token = "$h.$p." . Base64Url::encode('invalid_signature');

        $jwt->verify($mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\InvalidSignatureException
     */
    public function testHS256SignatureModified()
    {
        $jwt = new Jwt(new HS256());
        $token_strings = $jwt->sign($this->valid_claims, 'secret_key');

        list($h, $p, $s) = explode('.', $token_strings);
        $mod_token = "$h.$p." . Base64Url::encode('invalid_signature');

        $jwt->verify($mod_token, 'secret_key');
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\InvalidSignatureException
     */
    public function testES256SignatureModified()
    {
        $jwt = new Jwt(new ES256());
        $token_strings = $jwt->sign($this->valid_claims, $this->ec_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $mod_token = "$h.$p." . Base64Url::encode('invalid_signature');

        $jwt->verify($mod_token, $this->ec_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\UnexpectedValueException
     */
    public function testRS256NoMatchPrivateKeyType()
    {
        $jwt = new Jwt(new RS256());
        $jwt->sign($this->valid_claims, $this->ec_prv_key);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\UnexpectedValueException
     */
    public function testRS256NoMatchPublicKeyType()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        $jwt->verify($token_strings, $this->ec_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\UnexpectedValueException
     */
    public function testES256NoMatchPrivateKeyType()
    {
        $jwt = new Jwt(new ES256());
        $jwt->sign($this->valid_claims, $this->rsa_prv_key);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\UnexpectedValueException
     */
    public function testES256NoMatchPublicKeyType()
    {
        $jwt = new Jwt(new ES256());
        $token_strings = $jwt->sign($this->valid_claims, $this->ec_prv_key);

        $jwt->verify($token_strings, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\UnexpectedValueException
     */
    public function testRS256InvalidPrivateKey()
    {
        $jwt = new Jwt(new RS256());
        $jwt->sign($this->valid_claims, 'invalid_prv_key');
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\UnexpectedValueException
     */
    public function testRS256InvalidPublicKey()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        $jwt->verify($token_strings, 'invalid_pub_key');
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\InvalidSignatureException
     */
    public function testHS256InvalidSecretKey()
    {
        $jwt = new Jwt(new HS256());
        $token_strings = $jwt->sign($this->valid_claims, 'secret_key');

        $jwt->verify($token_strings, 'invalid_secret_key');
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\InvalidSignatureException
     */
    public function testRS256ModifiedHeaderTyp()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $header = Json::decode(Base64Url::decode($h));
        $header['typ'] = 'JOKE';
        $h = Base64Url::encode(Json::encode($header));
        $mod_token = "$h.$p.$s";

        $jwt->verify($mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Exception\MalformedException
     */
    public function testRS256ModifiedAlgHeaderNone()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $header = Json::decode(Base64Url::decode($h));
        $header['alg'] = 'none';
        $h = Base64Url::encode(Json::encode($header));
        $mod_token = "$h.$p.$s";

        $jwt->verify($mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Exception\MalformedException
     */
    public function testRS256ModifiedAlgHeaderNoMatch()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $header = Json::decode(Base64Url::decode($h));
        $header['alg'] = 'HS256';
        $h = Base64Url::encode(Json::encode($header));
        $mod_token = "$h.$p.$s";

        $jwt->verify($mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\InvalidSignatureException
     */
    public function testRS256ModifiedClaimExp()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_key);

        list($h, $p, $s) = explode('.', $token_strings);
        $payload = Json::decode(Base64Url::decode($p));
        $payload['exp'] = (time() + 86400);
        $p = Base64Url::encode(Json::encode($payload));
        $mod_token = "$h.$p.$s";

        $jwt->verify($mod_token, $this->rsa_pub_key);
    }

    /**
     * @expectedException Cyh\Jose\Exception\MalformedException
     */
    public function testRS256MalformedToken()
    {
        $jwt = new Jwt(new RS256);

        $jwt->verify('malformed_token_strings', $this->rsa_pub_key);
    }



    public function testRS256KeyIsPemStrSuccess()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_pem_str, 'password');

        $verified_claims = $jwt->verify($token_strings, $this->rsa_pub_pem_str);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    public function testES256KeyIsPemStrSuccess()
    {
        $jwt = new Jwt(new ES256());
        $token_strings = $jwt->sign($this->valid_claims, $this->ec_prv_pem_str);

        $verified_claims = $jwt->verify($token_strings, $this->ec_pub_pem_str);

        $this->assertEquals($this->valid_claims, $verified_claims);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\UnexpectedValueException
     */
    public function testRS256PrivateKeyIsPemStrInvalidKeyType()
    {
        $jwt = new Jwt(new RS256());
        $jwt->sign($this->valid_claims, $this->ec_prv_pem_str);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\UnexpectedValueException
     */
    public function testRS256PublicKeyIsPemStrInvalidKeyType()
    {
        $jwt = new Jwt(new RS256());
        $token_strings = $jwt->sign($this->valid_claims, $this->rsa_prv_pem_str);

        $jwt->verify($token_strings, $this->ec_pub_pem_str);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\UnexpectedValueException
     */
    public function testES256PrivateKeyIsPemStrInvalidKeyType()
    {
        $jwt = new Jwt(new ES256());
        $jwt->sign($this->valid_claims, $this->rsa_prv_pem_str);
    }

    /**
     * @expectedException Cyh\Jose\Signing\Exception\UnexpectedValueException
     */
    public function testES256PublicKeyIsPemStrInvalidKeyType()
    {
        $jwt = new Jwt(new ES256());
        $token_strings = $jwt->sign($this->valid_claims, $this->ec_prv_pem_str);

        $jwt->verify($token_strings, $this->rsa_pub_pem_str);
    }
}
