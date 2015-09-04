<?php
namespace Cyh\Jose\Encryption\Enc;

use Cyh\Jose\Encryption\ContentEncryptionKey;
use Cyh\Jose\Encryption\Random;
use Cyh\Jose\Utils\String;

abstract class AES_CBC_HS implements EncInterface
{
    /**
     * @param string $aad_base64
     * @param ContentEncryptionKey $cek
     * @param string $content
     * @return array array($iv, $cipher_text, $auth_tag)
     */
    public function encrypt($aad_base64, ContentEncryptionKey $cek, $content)
    {
        $iv = $this->generateIv();

        // Encrypt the plaintext with AES in CBC mode using PKCS #7 padding using the ENC_KEY above.
        $cipher_text = openssl_encrypt(
            $content, $this->getMethod(), $cek->getEncKey(), OPENSSL_RAW_DATA, $iv
        );
        $auth_tag = $this->createAuthenticationTag($aad_base64, $iv, $cipher_text, $cek);

        return array($iv, $cipher_text, $auth_tag);
    }

    /**
     * @param string $aad_base64
     * @param ContentEncryptionKey $cek
     * @param string $iv
     * @param string $cipher_text
     * @param string $auth_tag
     * @return string
     * @throws \Exception
     */
    public function decrypt($aad_base64, ContentEncryptionKey $cek, $iv, $cipher_text, $auth_tag)
    {
        $base_auth_tag = $this->createAuthenticationTag($aad_base64, $iv, $cipher_text, $cek);
        if (!String::equals($base_auth_tag, $auth_tag)) {
            throw new \Exception('Invalid authentication tag');
        }

        $content = openssl_decrypt(
            $cipher_text, $this->getMethod(), $cek->getEncKey(), OPENSSL_RAW_DATA, $iv
        );
        return $content;
    }

    /**
     * @param string $aad_base64
     * @param string $iv
     * @param string $cipher_text
     * @param ContentEncryptionKey $cek
     * @return string
     */
    protected function createAuthenticationTag(
        $aad_base64, $iv, $cipher_text, ContentEncryptionKey $cek
    )
    {
        // 64-Bit Big-Endian Representation of AAD Length
        $aad_length = String::len($aad_base64);
        if (version_compare(PHP_VERSION, '5.6.3', '>=')) {
            $al_value = pack('J1', $aad_length);

        } else {
            $int32bit_max = 2147483647;
            $al_value = pack('N2', (($aad_length / $int32bit_max) * 8), (($aad_length % $int32bit_max) * 8));
        }

        // Concatenate the AAD, the Initialization Vector, the ciphertext, and the AL value.
        $concatenated_value = implode('', array($aad_base64, $iv, $cipher_text, $al_value));

        // Compute the HMAC of the concatenated value above
        $hmac = hash_hmac($this->getHashAlgorithm(), $concatenated_value, $cek->getMacKey(), true);

        // Use the first half (128 bits) of the HMAC output M as the Authentication Tag output T.
        return String::substr($hmac, 0, 16);
    }

    /**
     * @return string
     */
    public function generateIv()
    {
        return Random::string(openssl_cipher_iv_length($this->getMethod()));
    }
}
