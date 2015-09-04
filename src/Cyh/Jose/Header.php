<?php
namespace Cyh\Jose;

use Cyh\Jose\Exception\UnexpectedValueException;
use Cyh\Jose\Utils\Json;
use Cyh\Jose\Utils\Base64Url;

class Header
{
    protected $headers = array();

    public function __construct(array $headers=array())
    {
        $this->headers = $headers;
    }

    public static function fromString($encoded_header)
    {
        $headers = Json::decode(Base64Url::decode($encoded_header));

        return new self($headers);
    }

    public function toString()
    {
        return $this->__toString();
    }

    public function __toString()
    {
        return Base64Url::encode(Json::encode($this->headers));
    }

    public function getTyp()
    {
        if (array_key_exists('typ', $this->headers)) {
            return $this->headers['typ'];
        }

        throw new UnexpectedValueException('Trying to get undefined property: typ');
    }

    public function getAlg()
    {
        if (array_key_exists('alg', $this->headers)) {
            return $this->headers['alg'];
        }

        throw new UnexpectedValueException('Trying to get undefined property: alg');
    }

    public function getEnc()
    {
        if (array_key_exists('enc', $this->headers)) {
            return $this->headers['enc'];
        }

        throw new UnexpectedValueException('Trying to get undefined property: enc');
    }
}
