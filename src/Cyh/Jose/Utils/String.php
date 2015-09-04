<?php
namespace Cyh\Jose\Utils;

class String
{
    /**
     * should be used to mitigate timing attacks.
     *
     * @param string $base_str
     * @param string $input_str
     * @return bool
     */
    public static function equals($base_str, $input_str)
    {
        // >= PHP 5.6.0
        if (function_exists('hash_equals')) {
            return hash_equals($base_str, $input_str);
        }

        $base_str_len = self::len($base_str);
        $input_str_len = self::len($input_str);
        if ($input_str_len !== $base_str_len) {
            return false;
        }

        $result = 0;
        for ($i = 0; $i < $base_str_len; ++$i) {
            $result |= (ord($base_str[$i]) ^ ord($input_str[$i]));
        }

        return 0 === $result;
    }

    /**
     * get number of bytes in strings.
     *
     * @param string $string
     * @return int
     */
    public static function len($string)
    {
        return mb_strlen($string, '8bit');
    }

    /**
     * substr of bytes
     *
     * @param string $string
     * @param int $offset
     * @param int $length
     * @return string
     */
    public static function substr($string, $offset, $length)
    {
        return mb_substr($string, $offset, $length, '8bit');
    }

    /*
    public static function paddingPkcs7($message, $block_length)
    {
        $pad = ($block_length - (mb_strlen($message, '8bit') % $block_length));
        $message .= str_repeat(chr($pad), $pad);

        return $message;
    }
    */
}
