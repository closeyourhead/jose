<?php
namespace Cyh\Jose\Validate;

use Cyh\Jose\Validate\Exception\ExpiredException;

/**
 * Class Expiration
 *
 * @package Cyh\Jose\Validate
 */
class Expiration implements ValidateInterface
{
    /**
     * @var \DateTime
     */
    private $now;

    /**
     * @param \DateTime|null $now
     */
    public function __construct(\DateTime $now=null)
    {
        $this->now = $now;
    }

    /**
     * @param array $payload
     * @return bool
     * @throws ExpiredException
     */
    public function validate(array $payload)
    {
        if ($this->now) {
            $now = $this->now;

        } else {
            $now = new \DateTime('now');
        }

        if (isset($payload['exp']) && $now->getTimestamp() < $payload['exp']) {
            return true;
        }

        throw new ExpiredException('Expired token');
    }

    /**
     * @return string
     */
    public function getName()
    {
        return 'exp';
    }
}
