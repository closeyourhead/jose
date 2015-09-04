<?php
namespace Cyh\Jose\Encryption\Enc;

use Cyh\Jose\Encryption\ContentEncryptionKey;

interface EncInterface
{
    /**
     * @return string
     */
    public function getEnc();

    /**
     * @return string
     */
    public function getMethod();

    /**
     * @return string
     */
    public function getHashAlgorithm();

    /**
     * @param string $aad_base64
     * @param ContentEncryptionKey $cek
     * @param string $content
     * @return array
     */
    public function encrypt($aad_base64, ContentEncryptionKey $cek, $content);

    /**
     * @param string $aad_base64
     * @param ContentEncryptionKey $cek
     * @param string $iv
     * @param string $cipher_text
     * @param string $auth_tag
     * @return string
     */
    public function decrypt($aad_base64, ContentEncryptionKey $cek, $iv, $cipher_text, $auth_tag);
}
