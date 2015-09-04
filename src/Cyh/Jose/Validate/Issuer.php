<?php
namespace Cyh\Jose\Validate;

use Cyh\Jose\Validate\Exception\InvalidIssuerException;

/**
 * Class Issuer
 *
 * @package Cyh\Jose\Validate
 */
class Issuer implements ValidateInterface
{
    /**
     * @var string
     */
    private $issuer;

    /**
     * @param string $issuer
     */
    public function __construct($issuer)
    {
        $this->issuer = $issuer;
    }

    /**
     * @param array $payload
     * @return true
     * @throws InvalidIssuerException
     */
    public function validate(array $payload)
    {
        if (!isset($payload['iss']) || strval($payload['iss']) !== $this->issuer) {
            throw new InvalidIssuerException('Invalid issuer');
        }

        return true;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return 'iss';
    }
}
