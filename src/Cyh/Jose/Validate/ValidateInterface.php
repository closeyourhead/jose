<?php
namespace Cyh\Jose\Validate;

use Cyh\Jose\Validate\Exception\ValidateException;

/**
 * Interface ValidateInterface
 *
 * @package Cyh\Jose\Validate
 */
interface ValidateInterface
{
    /**
     * @param array $payload
     * @return true
     * @throws ValidateException
     */
    public function validate(array $payload);

    /**
     * @return string
     */
    public function getName();
}
