<?php
namespace Cyh\Jose\Utils;

use Cyh\Jose\Exception\UnexpectedValueException;

class Base64Url
{
    /**
     * @param string $input
     * @return string
     * @throws UnexpectedValueException
     */
    public static function decode($input)
    {
        $remainder = (strlen($input) % 4);
        if ($remainder) {
            $pad_length = (4 - $remainder);
            $input .= str_repeat('=', $pad_length);
        }
        $result = base64_decode(strtr($input, '-_', '+/'));
        if (false === $result) {
            throw new UnexpectedValueException('Invalid base64 encoding');
        }

        return $result;
    }

    /**
     * @param string $input
     * @return string
     * @throws UnexpectedValueException
     */
    public static function encode($input)
    {
        if (!is_string($input)) {
            throw new UnexpectedValueException('base64 encode failed');
        }
        $encoded = base64_encode($input);
        $ret = rtrim(strtr($encoded, '+/', '-_'), '=');

        return $ret;
    }
}
