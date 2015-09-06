<?php
namespace Cyh\Jose\Encryption\Alg;

interface AlgInterface
{
    /**
     * @return string
     */
    public function getAlg();

    /**
     * @param string $cek
     * @param string $public_key_or_secret
     * @return string
     * @throws \Cyh\Jose\Encryption\Exception\UnexpectedValueException
     */
    public function encrypt($cek, $public_key_or_secret);

    /**
     * @param string $cek
     * @param string $private_key_or_secret
     * @param string $pass_phrase default null
     * @return string
     * @throws \Cyh\Jose\Encryption\Exception\UnexpectedValueException
     */
    public function decrypt($cek, $private_key_or_secret, $pass_phrase=null);
}
