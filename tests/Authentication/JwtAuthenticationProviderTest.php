<?php

namespace CultuurNet\SymfonySecurityJwt\Authentication;

use CultuurNet\UDB3\Jwt\JwtDecoderServiceInterface;
use Lcobucci\JWT\Token as Jwt;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class JwtAuthenticationProviderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var JwtDecoderServiceInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $decoderService;

    /**
     * @var JwtAuthenticationProvider
     */
    private $authenticationProvider;

    public function setUp()
    {
        $this->decoderService = $this->createMock(JwtDecoderServiceInterface::class);

        $this->authenticationProvider = new JwtAuthenticationProvider(
            $this->decoderService
        );
    }

    /**
     * @test
     */
    public function it_can_detect_which_token_it_supports()
    {
        $this->assertFalse(
            $this->authenticationProvider->supports(
                new AnonymousToken('key', 'user')
            )
        );

        $this->assertTrue(
            $this->authenticationProvider->supports(
                new JwtUserToken(
                    new Jwt()
                )
            )
        );
    }

    /**
     * @test
     */
    public function it_throws_an_exception_when_authenticating_an_unsupported_token()
    {
        $token = new AnonymousToken('key', 'user');

        $this->setExpectedException(
            AuthenticationException::class,
            "Token type Symfony\\Component\\Security\\Core\\Authentication\\Token\\AnonymousToken not supported."
        );

        $this->authenticationProvider->authenticate($token);
    }

    /**
     * @test
     */
    public function it_throws_an_exception_when_the_jwt_signature_is_invalid()
    {
        $jwt = new Jwt();
        $token = new JwtUserToken($jwt);

        $this->decoderService->expects($this->once())
            ->method('verifySignature')
            ->with($jwt)
            ->willReturn(false);

        $this->setExpectedException(
            AuthenticationException::class,
            "Token signature verification failed. The token is likely forged or manipulated."
        );

        $this->authenticationProvider->authenticate($token);
    }

    /**
     * @test
     */
    public function it_throws_an_exception_when_the_jwt_data_is_invalid()
    {
        $jwt = new Jwt();
        $token = new JwtUserToken($jwt);

        $this->decoderService->expects($this->once())
            ->method('verifySignature')
            ->with($jwt)
            ->willReturn(true);

        $this->decoderService->expects($this->once())
            ->method('validateData')
            ->with($jwt)
            ->willReturn(false);

        $this->setExpectedException(
            AuthenticationException::class,
            "Token claims validation failed. This most likely means the token is expired."
        );

        $this->authenticationProvider->authenticate($token);
    }

    /**
     * @test
     */
    public function it_throws_an_exception_when_the_jwt_is_missing_required_claims()
    {
        $jwt = new Jwt();
        $token = new JwtUserToken($jwt);

        $this->decoderService->expects($this->once())
            ->method('verifySignature')
            ->with($jwt)
            ->willReturn(true);

        $this->decoderService->expects($this->once())
            ->method('validateData')
            ->with($jwt)
            ->willReturn(true);

        $this->decoderService->expects($this->once())
            ->method('validateRequiredClaims')
            ->with($jwt)
            ->willReturn(false);

        $this->setExpectedException(
            AuthenticationException::class,
            "Token is missing one of its required claims."
        );

        $this->authenticationProvider->authenticate($token);
    }

    /**
     * @test
     */
    public function it_returns_an_authenticated_token_when_the_jwt_is_valid()
    {
        $jwt = new Jwt();
        $token = new JwtUserToken($jwt);

        $this->decoderService->expects($this->once())
            ->method('verifySignature')
            ->with($jwt)
            ->willReturn(true);

        $this->decoderService->expects($this->once())
            ->method('validateData')
            ->with($jwt)
            ->willReturn(true);

        $this->decoderService->expects($this->once())
            ->method('validateRequiredClaims')
            ->with($jwt)
            ->willReturn(true);

        $authToken = $this->authenticationProvider->authenticate($token);

        $this->assertEquals($jwt, $authToken->getCredentials());
        $this->assertTrue($authToken->isAuthenticated());
    }
}
