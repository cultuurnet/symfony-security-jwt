<?php

namespace CultuurNet\SymfonySecurityJwt\Authentication;

use CultuurNet\UDB3\Jwt\JwtDecoderService;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class JwtAuthenticationProvider implements AuthenticationProviderInterface
{
    /**
     * @var JwtDecoderService
     */
    private $decoderService;

    /**
     * @var array
     */
    private $requiredClaims;

    /**
     * @param JwtDecoderService $decoderService
     * @param string[] $requiredClaims
     */
    public function __construct(
        JwtDecoderService $decoderService,
        array $requiredClaims = []
    ) {
        $this->decoderService = $decoderService;
        $this->requiredClaims = $requiredClaims;

        $stringClaims = array_filter($this->requiredClaims, 'is_string');
        if (count($stringClaims) !== count($requiredClaims)) {
            throw new \InvalidArgumentException(
                "All required claims should be strings."
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof JwtUserToken;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        /* @var JwtUserToken $token */
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

        foreach ($this->requiredClaims as $claim) {
            if (!$jwt->hasClaim($claim)) {
                throw new AuthenticationException(
                    "Token is missing a {$claim} claim."
                );
            }
        }

        return new JwtUserToken($jwt, true);
    }
}
