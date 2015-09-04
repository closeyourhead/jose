<?php
namespace Cyh\Jose;

use Cyh\Jose\Exception\MalformedException;
use Cyh\Jose\Exception\UnexpectedValueException;
use Cyh\Jose\Signing\Signer\SignerInterface;
use Cyh\Jose\Signing\Exception\InvalidSignatureException;
use Cyh\Jose\Validate\ValidateInterface;
use Cyh\Jose\Validate\Exception\ValidateException;
use Cyh\Jose\Utils\Json;
use Cyh\Jose\Utils\Base64Url;

class Jwt
{
    /**
     * @param \Cyh\Jose\Signing\Signer\SignerInterface $signer
     * @param mixed $claims
     * @param resource|string $key default null
     * @param string $pass_phrase default null
     * @return string
     * @throws UnexpectedValueException
     * @throws InvalidSignatureException
     */
    public static function sign(SignerInterface $signer, $claims, $key=null, $pass_phrase=null)
    {
        $header_arr = array(
            'typ' => 'JWT',
            'alg' => $signer->getAlg(),
        );

        $header = new Header($header_arr);
        $message = $header->toString() . '.' . Base64Url::encode(Json::encode($claims));

        $signature = $signer->sign($message, $key, $pass_phrase);
        $signature_base64 = Base64Url::encode($signature);

        return $message . '.' . $signature_base64;
    }

    /**
     * @param \Cyh\Jose\Signing\Signer\SignerInterface $signer
     * @param string $jwt_strings
     * @param resource|string $key default null
     * @param ValidateInterface[] $validators
     * @return array
     * @throws MalformedException
     * @throws InvalidSignatureException
     * @throws ValidateException
     */
    public static function verify(SignerInterface $signer, $jwt_strings, $key=null, array $validators=array())
    {
        $jwt_arr = explode('.', $jwt_strings);
        if (3 !== count($jwt_arr)) {
            throw new MalformedException('Wrong number of segments');
        }

        $header_base64 = $jwt_arr[0];
        $header = Header::fromString($header_base64);

        // Do not determine algorithm by header.
        if ($signer->getAlg() !== $header->getAlg()) {
            throw new MalformedException('Invalid alg header');
        }

        $payload_base64 = $jwt_arr[1];
        $message = $header_base64 . '.' . $payload_base64;
        $signature = Base64Url::decode($jwt_arr[2]);
        $signer->verify($message, $signature, $key);

        $payload_json = Base64Url::decode($payload_base64);
        $claims = Json::decode($payload_json);

        foreach ($validators as $validator) {
            if (!$validator instanceof ValidateInterface) {
                throw new UnexpectedValueException('validator is must implement ValidateInterface');
            }
            if (!$validator->validate($claims)) {
                throw new ValidateException('Validation failed. validator name: ' . $validator->getName());
            }
        }

        return $claims;
    }
}
