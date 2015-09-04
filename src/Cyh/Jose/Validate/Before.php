<?php
namespace Cyh\Jose\Validate;

use Cyh\Jose\Validate\Exception\BeforeException;

/**
 * Class Before
 *
 * @package Cyh\Jose\Validate
 */
class Before implements ValidateInterface
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
     * @return true
     * @throws BeforeException
     */
    public function validate(array $payload)
    {
        if ($this->now) {
            $now = $this->now;

        } else {
            $now = new \DateTime('now');
        }

        if (isset($payload['nbf']) && $now->getTimestamp() > intval($payload['nbf'])) {
            return true;
        }

        throw new BeforeException('Token is not yet available');
    }

    /**
     * @return string
     */
    public function getName()
    {
        return 'nbf';
    }
}
