<?php
namespace Cyh\Jose\Utils;

use Cyh\Jose\Exception\UnexpectedValueException;

class Json
{
    /**
     * @param string $json_strings
     * @return mixed
     */
    public static function decode($json_strings)
    {
        $result = json_decode($json_strings, true);
        if (JSON_ERROR_NONE !== ($err = json_last_error())) {
            throw new UnexpectedValueException('decodeJson failed: ' . self::getLastErrorMessage($err));
        }

        return $result;
    }

    /**
     * @param mixed $input
     * @return string
     */
    public static function encode($input)
    {
        $json_strings = json_encode($input, JSON_UNESCAPED_SLASHES);
        if (JSON_ERROR_NONE !== ($err = json_last_error())) {
            throw new UnexpectedValueException('encodeJson failed: ' . self::getLastErrorMessage($err));
        }

        return $json_strings;
    }

    /**
     * getLastErrorMessage
     * wrapper for php json_last_error_msg
     *
     * @link http://php.net/manual/en/function.json-last-error-msg.php
     * @link http://php.net/manual/en/function.json-last-error.php
     *
     * @param int $err json_last_error result
     * @return string|int
     */
    public static function getLastErrorMessage($err)
    {
        if (function_exists('json_last_error_msg')) {
            return json_last_error_msg();
        }

        return $err;
    }
}
