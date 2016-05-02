<?php

namespace CultuurNet\SymfonySecurityJwt\Authentication;

use Lcobucci\JWT\Token as Jwt;

class JwtUserTokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function it_returns_the_jwt_as_credentials()
    {
        $jwt = new Jwt(
            ['alg' => 'none'],
            [],
            null,
            $payload = ['header', 'payload']
        );

        $jwtUserToken = new JwtUserToken($jwt);

        $this->assertEquals($jwt, $jwtUserToken->getCredentials());
    }

    /**
     * @test
     */
    public function it_can_be_set_as_authenticated()
    {
        $jwtUserToken = new JwtUserToken(new Jwt(), true);
        $this->assertTrue($jwtUserToken->isAuthenticated());
    }
}
