<?php

namespace CultuurNet\SymfonySecurityJWT\Authentication;

use CultuurNet\UDB3\Jwt\JwtDecoderService;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class JWTAuthenticationProvider implements AuthenticationProviderInterface
{
    /**
     * @var JwtDecoderService
     */
    private $decoderService;

    /**
     * @param JwtDecoderService $decoderService
     */
    public function __construct(
        JwtDecoderService $decoderService
    ) {
        $this->decoderService = $decoderService;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof JWTUserToken;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        /* @var JWTUserToken $token */
        if (!$this->supports($token)) {
            throw new AuthenticationException(
                "Token type " . get_class($token) . " not supported."
            );
        }

        $jwt = $token->getCredentials();

        if (!$this->decoderService->verifySignature($jwt)) {
            throw new AuthenticationException(
                "Token signature verification failed. The token is likely forged or manipulated."
            );
        }

        if (!$this->decoderService->validateData($jwt)) {
            throw new AuthenticationException(
                "Token claims validation failed. This most likely means the token is expired."
            );
        }

        $requiredClaims = [
            'uid',
            'nick',
            'email',
        ];

        foreach ($requiredClaims as $claim) {
            if (!$jwt->hasClaim($claim)) {
                throw new AuthenticationException(
                    "Token is missing a {$claim} claim."
                );
            }
        }

        return new JWTUserToken($jwt, true);
    }
}
