<?php

namespace CultuurNet\SymfonySecurityJwt\Firewall;

use CultuurNet\SymfonySecurityJwt\Authentication\JwtUserToken;
use CultuurNet\UDB3\Jwt\JwtDecoderServiceInterface;
use Lcobucci\JWT\Token as Jwt;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use ValueObjects\StringLiteral\StringLiteral;

class JwtListenerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var TokenStorageInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $tokenStorage;

    /**
     * @var AuthenticationManagerInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $authenticationManager;

    /**
     * @var JwtDecoderServiceInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $jwtDecoderService;

    /**
     * @var JwtListener
     */
    private $listener;

    /**
     * @var GetResponseEvent|\PHPUnit_Framework_MockObject_MockObject
     */
    private $getResponseEvent;

    public function setUp()
    {
        $this->tokenStorage = $this->getMock(TokenStorageInterface::class);
        $this->authenticationManager = $this->getMock(AuthenticationManagerInterface::class);
        $this->jwtDecoderService = $this->getMock(JwtDecoderServiceInterface::class);

        $this->listener = new JwtListener(
            $this->tokenStorage,
            $this->authenticationManager,
            $this->jwtDecoderService
        );

        $this->getResponseEvent = $this->getMock(GetResponseEvent::class, [], [], '', false);
    }

    /**
     * @test
     * @dataProvider irrelevantRequestProvider
     *
     * @param Request $request
     */
    public function it_ignores_irrelevant_requests(Request $request)
    {
        $this->getResponseEvent->expects($this->any())
            ->method('getRequest')
            ->willReturn($request);

        $this->jwtDecoderService->expects($this->never())
            ->method('parse');

        $this->authenticationManager->expects($this->never())
            ->method('authenticate');

        $this->tokenStorage->expects($this->never())
            ->method('setToken');

        $this->listener->handle($this->getResponseEvent);
    }

    /**
     * @return array
     */
    public function irrelevantRequestProvider()
    {
        return [
            [
                new Request([], [], [], [], [], [], ''),
            ],
            [
                new Request([], [], [], [], [], ['HTTP_AUTHORIZATION' => 'foo'], ''),
            ],
        ];
    }

    /**
     * @test
     */
    public function it_authenticates_and_stores_valid_tokens()
    {
        $tokenString = 'headers.payload.signature';

        $jwt = new Jwt(
            ['alg' => 'none'],
            [],
            null,
            ['headers', 'payload']
        );

        $token = new JwtUserToken($jwt);
        $authenticatedToken = new JwtUserToken($jwt, true);

        $request = new Request(
            [],
            [],
            [],
            [],
            [],
            ['HTTP_AUTHORIZATION' => 'Bearer ' . $tokenString],
            ''
        );

        $this->getResponseEvent->expects($this->any())
            ->method('getRequest')
            ->willReturn($request);

        $this->jwtDecoderService->expects($this->once())
            ->method('parse')
            ->with(
                new StringLiteral($tokenString)
            )
            ->willReturn($jwt);

        $this->authenticationManager->expects($this->once())
            ->method('authenticate')
            ->with($token)
            ->willReturn($authenticatedToken);

        $this->tokenStorage->expects($this->once())
            ->method('setToken')
            ->with($authenticatedToken);

        $this->listener->handle($this->getResponseEvent);
    }

    /**
     * @test
     */
    public function it_returns_an_unauthorized_response_if_jwt_authentication_fails()
    {
        $tokenString = 'headers.payload.signature';

        $jwt = new Jwt(
            ['alg' => 'none'],
            [],
            null,
            ['headers', 'payload']
        );

        $token = new JwtUserToken($jwt);

        $request = new Request(
            [],
            [],
            [],
            [],
            [],
            ['HTTP_AUTHORIZATION' => 'Bearer ' . $tokenString],
            ''
        );

        $this->getResponseEvent->expects($this->any())
            ->method('getRequest')
            ->willReturn($request);

        $this->jwtDecoderService->expects($this->once())
            ->method('parse')
            ->with(
                new StringLiteral($tokenString)
            )
            ->willReturn($jwt);

        $authenticationException = new AuthenticationException(
            'Authentication failed',
            666
        );

        $this->authenticationManager->expects($this->once())
            ->method('authenticate')
            ->with($token)
            ->willThrowException($authenticationException);

        $this->getResponseEvent->expects($this->once())
            ->method('setResponse')
            ->willReturnCallback(
                function (Response $response) {
                    $this->assertEquals('Authentication failed', $response->getContent());
                    $this->assertEquals(401, $response->getStatusCode());
                }
            );

        $this->listener->handle($this->getResponseEvent);
    }
}
