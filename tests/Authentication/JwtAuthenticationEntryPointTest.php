<?php

namespace CultuurNet\SymfonySecurityJwt\Authentication;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class JwtAuthenticationEntryPointTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var JwtAuthenticationEntryPoint
     */
    private $entryPoint;

    public function setUp()
    {
        $this->entryPoint = new JwtAuthenticationEntryPoint();
    }

    /**
     * @test
     */
    public function it_returns_a_response_with_status_401_and_a_json_body()
    {
        $request = new Request();
        $exception = new AuthenticationException('JWT is expired.');

        $expectedBody = json_encode(
            [
                'error' => 'Unauthorized',
                'details' => 'JWT is expired.',
            ]
        );

        $response = $this->entryPoint->start($request, $exception);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals($expectedBody, $response->getContent());
    }
}
