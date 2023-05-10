<?php

namespace Jk\CidaasHelper\Util;

use Shopware\Core\Framework\Struct\Struct;

class CidaasStruct extends Struct 
{   
    private $state;
    private $authCode;
    private $customerId;
    private $sub;

    public function __construct(String $state, ?String $authCode=null, ?String $customerId=null, ?String $sub=null)
    {
        $this->state = $state;
        $this->authCode = $authCode;
        $this->customerId = $customerId;
        $this->sub = $sub;
    }

    public function getState(): ?String
    {
        return $this->state;
    }
    public function setState(?String $state): void
    {
        $this->state = $state;
    }

    public function getAuthCode(): ?String
    {
        return $this->authCode;
    }
    public function setAuthCode(?String $authCode): void
    {
        $this->authCode = $authCode;
    }

    public function getCustomerId(): ?String
    {
        return $this->customerId;
    }
    public function setCustomerId(?String $customerId): void
    {
        $this->customerId = $customerId;
    }

    public function getSub(): ?String
    {
        return $this->sub;
    }
    public function setSub(?String $sub): void
    {
        $this->sub = $sub;
    }
}