<?php
namespace Cyh\Jose\Encryption;

class Random
{
    /**
     * Generate a pseudo-random string of bytes
     *
     * @link http://php.net/manual/en/function.openssl-random-pseudo-bytes.php
     *
     * @param int $length
     * @return string
     */
    public static function string($length)
    {
        return openssl_random_pseudo_bytes($length, $is_strong);
    }
}
