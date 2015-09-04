<?php
namespace Cyh\Jose\Validate;

use Cyh\Jose\Validate\Exception\InvalidAudienceException;

/**
 * Class Audience
 *
 * @package Cyh\Jose\Validate
 */
class Audience implements ValidateInterface
{
    /**
     * @var string
     */
    private $audience;

    /**
     * @param string $audience
     */
    public function __construct($audience)
    {
        $this->audience = $audience;
    }

    /**
     * @param array $payload
     * @return true
     * @throws InvalidAudienceException
     */
    public function validate(array $payload)
    {
        if (!isset($payload['aud']) || strval($payload['aud']) !== $this->audience) {
            throw new InvalidAudienceException('Invalid audience');
        }

        return true;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return 'aud';
    }
}
