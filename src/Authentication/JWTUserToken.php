<?php
/**
 * @file
 */

namespace CultuurNet\SymfonySecurityJWT\Authentication;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class JWTUserToken extends AbstractToken
{
    public function getCredentials()
    {
        // TODO: Implement getCredentials() method.
    }
}
