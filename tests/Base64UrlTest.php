<?php
namespace Cyh\Jose\Tests;

use Cyh\Jose\Utils\Base64Url;

class Base64UrlTest extends \PHPUnit_Framework_TestCase
{
    public function testEncodeDecodeBase64UrlSuccess()
    {
        $input = 'http://www.example.com/====+/-_';

        $encoded = Base64Url::encode($input);
        $decoded = Base64Url::decode($encoded);

        $this->assertContains('+', $decoded);
        $this->assertContains('/', $decoded);
        $this->assertContains('=', $decoded);

        $this->assertEquals($decoded, $input);
    }

    /**
     * @expectedException \Cyh\Jose\Exception\UnexpectedValueException
     */
    public function testDecodeBase64InvalidParam()
    {
        Base64Url::decode('A');
    }

    /**
     * @expectedException \Cyh\Jose\Exception\UnexpectedValueException
     */
    public function testEncodeBase64InvalidParam()
    {
        Base64Url::encode(array());
    }
}
