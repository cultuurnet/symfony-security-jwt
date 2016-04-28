<?php
/**
 * @file
 */

namespace CultuurNet\SymfonySecurityJWT\Authentication;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class JWTProvider implements AuthenticationProviderInterface
{
    public function supports(TokenInterface $token)
    {
        return $token instanceof JWTUserToken;
    }

    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return;
        }
    }
}
