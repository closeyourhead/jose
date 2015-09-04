<?php
namespace Cyh\Jose\Encryption;

use Cyh\Jose\Utils\String;

class ContentEncryptionKey
{
    /**
     * @var string
     */
    private $content_encryption_key;

    /**
     * @var string
     */
    private $mac_key;

    /**
     * @var string
     */
    private $enc_key;

    /**
     * @param string $cek
     */
    public function __construct($cek=null)
    {
        if (null === $cek) {
            // generate 256bits random cek,
            $this->content_encryption_key = Random::string(32);

        } else {
            $this->content_encryption_key = $cek;
        }
    }

    /**
     * @return string
     */
    public function getCek()
    {
        return $this->content_encryption_key;
    }

    /**
     * @return string
     */
    public function getMacKey()
    {
        if (!$this->mac_key) {
            // Use the first 128 bits of this key as the HMAC SHA-256 key MAC_KEY
            $this->mac_key = String::substr($this->content_encryption_key, 0, 16);
        }
        return $this->mac_key;
    }

    /**
     * @return string
     */
    public function getEncKey()
    {
        if (!$this->enc_key) {
            // Use the last 128 bits of this key as the AES-CBC key ENC_KEY
            $this->enc_key = String::substr($this->content_encryption_key, 16, null);
        }
        return $this->enc_key;
    }
}
