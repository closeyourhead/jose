<?php
namespace Cyh\Jose;

use Cyh\Jose\Encryption\Alg\AlgInterface;
use Cyh\Jose\Encryption\Enc\EncInterface;
use Cyh\Jose\Encryption\ContentEncryptionKey;
use Cyh\Jose\Exception\MalformedException;
use Cyh\Jose\Utils\Base64Url;

class Jwe
{
    /**
     * @param AlgInterface $alg
     * @param EncInterface $enc
     * @param string $content
     * @param string $public_or_secret_key
     * @return string
     */
    public static function encrypt(AlgInterface $alg, EncInterface $enc, $content, $public_or_secret_key)
    {
        $protected_header = new Header(array('alg' => $alg->getAlg(), 'enc' => $enc->getEnc()));
        $aad_base64 = $protected_header->toString();

        $cek = new ContentEncryptionKey();
        $encrypted_cek = $alg->encrypt($cek->getCek(), $public_or_secret_key);

        list($iv, $cipher_text, $auth_tag) = $enc->encrypt($aad_base64, $cek, $content);

        return implode('.', [
            $aad_base64,
            Base64Url::encode($encrypted_cek),
            Base64Url::encode($iv),
            Base64Url::encode($cipher_text),
            Base64Url::encode($auth_tag)
        ]);
    }

    /**
     * @param AlgInterface $alg
     * @param EncInterface $enc
     * @param string $content
     * @param string $private_or_secret_key
     * @param string $pass_phrase default null
     * @return string
     * @throws \Exception
     */
    public static function decrypt(
        AlgInterface $alg, EncInterface $enc, $content, $private_or_secret_key, $pass_phrase=null
    )
    {
        $components = explode('.', $content);
        if (5 !== count($components)) {
            throw new MalformedException('Wrong number of segments');
        }

        $encrypted_cek = Base64Url::decode($components[1]);
        $cek = new ContentEncryptionKey($alg->decrypt($encrypted_cek, $private_or_secret_key, $pass_phrase));

        $aad_base64 = $components[0];
        $protected_header = Header::fromString($components[0]);

        if ($alg->getAlg() !== $protected_header->getAlg()) {
            throw new MalformedException('invalid alg header');
        }
        if ($enc->getEnc() !== $protected_header->getEnc()) {
            throw new MalformedException('invalid enc header');
        }

        $iv = Base64Url::decode($components[2]);
        $cipher_text = Base64Url::decode($components[3]);
        $auth_tag = Base64Url::decode($components[4]);

        return $enc->decrypt($aad_base64, $cek, $iv, $cipher_text, $auth_tag);
    }
}
