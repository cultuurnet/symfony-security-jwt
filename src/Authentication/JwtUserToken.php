<?php

namespace CultuurNet\SymfonySecurityJwt\Authentication;

use Lcobucci\JWT\Token as Jwt;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class JwtUserToken extends AbstractToken
{
    /**
     * @var Jwt
     */
    private $jwt;

    /**
     * @param Jwt $jwt
     * @param bool $authenticated
     */
    public function __construct(Jwt $jwt, $authenticated = false)
    {
        parent::__construct();
        $this->setAuthenticated($authenticated);
        $this->jwt = $jwt;
    }

    /**
     * @return Jwt
     */
    public function getCredentials()
    {
        return $this->jwt;
    }
}
