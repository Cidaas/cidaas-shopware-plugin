<?php declare(strict_types = 1);

/**
 *  needed data:
 *  Env => settings
 *  storename=StoreId => settings
 *  shared Secret => settings
 *  api_user => WS{storeId}._.1
 *  api_user_pw => settings
 */


namespace Cidaas\OauthConnect\Service;

use Shopware\Core\System\SystemConfig\SystemConfigService;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Checkout\Customer\Event\CustomerBeforeLoginEvent;
use Shopware\Core\Checkout\Customer\Event\CustomerLoginEvent;
use Shopware\Core\Checkout\Customer\Exception\BadCredentialsException;
use Shopware\Core\Checkout\Customer\Exception\CustomerAuthThrottledException;
use Shopware\Core\Checkout\Customer\Exception\CustomerNotFoundException;
use Shopware\Core\Checkout\Customer\Exception\InactiveCustomerException;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\System\SalesChannel\ContextTokenResponse;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use Shopware\Core\System\SalesChannel\Context\CartRestorer;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;

use Shopware\Core\Checkout\Customer\SalesChannel\AbstractRegisterRoute;
use Shopware\Core\Framework\Validation\Exception\ConstraintViolationException;
use Shopware\Core\PlatformRequest;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\System\Country\CountryEntity;
use Shopware\Core\System\Country\Exception\CountryNotFoundException;
use Cidaas\OauthConnect\Util\CidaasStruct;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\FetchMode;


class CidaasLoginService {

    private $eventDispatcher;
    private $customerRepo;
    private $customerGroupRepo;
    private $customerAddressRepo;
    private $customerGroupTranslationRepo;
    private $countryRepository;
    private $contextRestorer;
    private $sysConfig;

    private $wellKnown = '/.well-known/openid-configuration';
    private $wellKnownUrl;
    private $oAuthEndpoints;
    private $client;

    private $connection;

    private $registerRoute;

    private $clientId;
    private $clientSecret;
    private $nonInteractiveClientId;
    private $nonInteractiveClientSecret;

    private $cidaasUrl;

    private $state = '';
    private $cfCustomerNumber = '';
    private $defaultGroup = '';

    public function __construct(
        EventDispatcherInterface $eventDispatcher,
        EntityRepository $customerRepo,
        CartRestorer     $contextRestorer,
        SystemConfigService $sysConfig,
        Connection $connection,
        AbstractRegisterRoute $registerRoute,
        EntityRepository $customerGroupRepo,
        EntityRepository $customerAddressRepo,
        EntityRepository $customerGroupTranslationRepo,
        EntityRepository $countryRepository
        )
        {
            $this->eventDispatcher = $eventDispatcher;
            $this->customerRepo = $customerRepo;
            $this->customerGroupRepo = $customerGroupRepo;
            $this->customerAddressRepo = $customerAddressRepo;
            $this->customerGroupTranslationRepo = $customerGroupTranslationRepo;
            $this->countryRepository = $countryRepository;
            $this->sysConfig = $sysConfig;
            $this->wellKnownUrl = $sysConfig->get('CidaasOauthConnect.config.baseUri').$this->wellKnown;
            $client = new Client();
            $res = $client->get($this->wellKnownUrl);
            $this->oAuthEndpoints = json_decode($res->getBody()->getContents());
            $this->clientId = $sysConfig->get('CidaasOauthConnect.config.clientId');
            $this->clientSecret = $sysConfig->get('CidaasOauthConnect.config.clientSecret');
            $this->nonInteractiveClientId = $sysConfig->get('CidaasOauthConnect.config.nonInteractiveClientId');
            $this->nonInteractiveClientSecret = $sysConfig->get('CidaasOauthConnect.config.nonInteractiveClientSecret');

            $this->cidaasUrl = $sysConfig->get('CidaasOauthConnect.config.baseUri');
            $this->cfCustomerNumber = $sysConfig->get('CidaasOauthConnect.config.CfCustomernumber');
            $this->defaultGroup = $sysConfig->get('CidaasOauthConnect.config.customergroupDefault');
            
            $this->connection = $connection;
            $this->registerRoute = $registerRoute;
            $this->contextRestorer = $contextRestorer;

        }

    public function getWellKnown()
    {
        return $this->wellKnownUrl;
    }

    public function getOAuthEndpoints()
    {
        return $this->oAuthEndpoints;
    }

    public function getState(): String
    {
        return $this->state;
    }

    public function login($email, $context)
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('customer.email', $email));
        $customer = $this->customerRepo->search($criteria, $context->getContext())->first();

        $context = $this->contextRestorer->restore($customer->getId(), $context);
        $newToken = $context->getToken();

        $this->customerRepo->update([
            [
                'id' => $customer->getId(),
                'lastLogin' => new \DateTimeImmutable(),
            ],
        ], $context->getContext());

        $event = new CustomerLoginEvent($context, $customer, $newToken);
        $this->eventDispatcher->dispatch($event);

        return new ContextTokenResponse($newToken);
    }

    public function loginBySub($sub, $context, $email=null): ContextTokenResponse
    {
        if ($email !== null) {
            $event = new CustomerBeforeLoginEvent($context, $email);
            $this->eventDispatcher($event);
        }
        try {
            $customer = $this->getCustomerBySub($sub, $context);
        }
        catch (BadCredentialsException $ex) {
            throw new UnauthorizedHttpException('json', $exception->getMessage());
        }
        $context = $this->contextRestorer->restore($customer->getId(), $context);
        $newToken = $context->getToken();
        $this->customerRepo->update([
            [
                'id' => $customer->getId(),
                'lastLogin' => new \DateTimeImmutable(),
            ],
        ], $context->getContext());
        $event = new CustomerLoginEvent($context, $customer, $newToken);
        $this->eventDispatcher->dispatch($event);
        return new ContextTokenResponse($newToken);
    }

    public function getCustomerBySub($sub, $context) {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('customer.customFields.sub', $sub));
        $customers = $this->customerRepo->search($criteria, $context->getContext());
        if ($customers->count() !== 1) {
            throw new BadCredentialsException();
        }
        return $customers->first();
    }

    public function getCustomerByEmail($email, $context) {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('customer.email', $email));
        $customer = $this->customerRepo->search($criteria, $context->getContext())->first();
        return $customer;
    }

    public function customerExistsBySub($sub, $context)
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('customer.customFields.sub', $sub));
        $customers = $this->customerRepo->search($criteria, $context->getContext());
        if ($customers->count() < 1) {
            return false;
        }
        return true;
    }

    public function customerExistsByEmail($email, $context)
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('customer.email', $email));
        $customers = $this->customerRepo->search($criteria, $context->getContext());
        if ($customers->count() < 1) {
            return array(
                "exists" => false
            );
        }
        return array(
            "exists" => true,
            "id" => $customers->first()->getId(),
            "lastLogin" => $customers->first()->getLastLogin()
        );
    }

    public function customerExistsInCidaas($email, $requestId, $context)
    {
        $target =  $this->cidaasUrl + '/users-srv/user/checkexists/'.$requestId;
        $client = new Client();
        $resp = $client->post($target, [
            'form_params' => [
                'email'=>$email,
                'requestId' => $requestId
            ]
            ]);
        return json_decode($resp->getBody()->getContents());
    }

    public function getLastLogin($customerId, $context)
    {
        $customer = $this->customerRepo->search(new Criteria([$customerId]), $context->getContext())->first();
        return $customer->getLastLogin();
    }

    public function getAuthorizationUri($state, $url, $email=null): String
    {
        $redirectUri = $url.'/cidaas/redirect';
        $result = $this->oAuthEndpoints->authorization_endpoint 
            . '?scope='. urlencode("openid email profile group") .'&response_type=code'
            . '&approval_prompt=auto&redirect_uri='. urlencode($redirectUri) 
            . '&client_id='.$this->clientId . '&state='.$state;
        if ($email !== null) {
            $result .= '&userIdHint='.$email . '&type=email';
        }
        return $result;

    }

    public function getRegisterUri($state, $url, $userIdHint=null, $type=null): String
    {
        $redirectUri = $url.'/cidaas/redirect';
        $result = $this->oAuthEndpoints->authorization_endpoint . '?scope='
            . urlencode("openid email profile") . '&client_id='.$this->clientId
            . '&response_type=code&approval_prompt=auto&redirect_uri='
            . urlencode($redirectUri)
            . '&view_type=register'
            . '&state='.$state;
        if ($userIdHint !== null) {
            $result .= '&userIdHint='.$userIdHint
            .'&type='.$type;
        }
        return $result;
    }

    public function getClientId() {
        return $this->clientId;
    }

    public function registerExistingUser($user, $context, $url)
    {
        $randomPassword = $this->generateRandomString(14);
        $salutation = $this->getSalutationId($user['customFields']['salutation']);
        $country = $this->getCountryId($user['customFields']['billing_address_country']);
        $data = new RequestDataBag([
            "guest" => false,
            "salutationId" => $salutation,
            "firstName" => $user['given_name'],
            "lastName" => $user['family_name'],
            "email" => $user['email'],
            'defaultBillingAddressId' => Uuid::randomHex(),
            'defaultShippingAddressId' => Uuid::randomHex(),
            "password" => $randomPassword,
            "accountType" => 'private',
            "acceptedDataProtection" => true,
            "billingAddress" => array(
                "countryId" => $country,
                "street" => $user['customFields']['billing_address_street'],
                "zipcode" => $user['customFields']['billing_address_zipcode'],
                "city" => $user['customFields']['billing_address_city']
            ),
            "storefrontUrl" => $url
        ]);
        $regres = $this->registerRoute->register($data, $context, false);
        $customer = $this->getCustomerByEmail($user['email'], $context);
        $mitglied = false;
        $mitarbeiter = false;
        $mitarbeiterPromo = false;
        $updateData = [
            'id' => $customer->getId(),
                'lastLogin' => new \DateTimeImmutable(),
                'customFields' => [
                    'sub' => $user['sub']]
        ];
        if ($this->cfCustomerNumber) {
            if ($this->cfCustomerNumber !== '') {
                $updateData['customerNumber'] = $user['customFields'][$this->cfCustomerNumber];    
            }
        }
        $this->customerRepo->upsert([
            $updateData
        ], $context->getContext());
        
        return $data;
    }

    public function getAccountFromCidaas($token)
    {
        $client = new Client();
        $response = $client->get($this->oAuthEndpoints->userinfo_endpoint, [
            'headers' => [
                'content_type' => 'application/json',
                'Authorization' => 'Bearer '.$token
                
            ]
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }

    public function endSession($token)
    {
        $client = new Client();
        $client->get($this->oAuthEndpoints->end_session_endpoint. '?access_token_hint='.$token,
        ['headers' => [
            'content_type' => 'application/json'
            ]
        ]
        );
    }

    public function getSysConfig($name, $param=null)
    {
        if ($param !== null) {
            return $this->sysConfig->get($name, $param);
        }
        return $this->sysConfig->get($name);
    }

    public function getCidaasUrl(): String
    {
        return $this->cidaasUrl;
    }

    public function changeEmail($email, $sub, $context)
    {
        $client = new Client();
        $customer = $this->getCustomerBySub($sub, $context);
        $adminToken = $this->getAdminToken();
        try {
            $resp = $client->put($this->cidaasUrl.'/users-srv/user/'.$sub, [
                'headers' => [
                    'Authorization' => 'Bearer '.$adminToken->access_token
                ],
                'form_params' => [
                    'email' => $email,
                    'sub' => $sub,
                    'provider' => 'self',
                    'email_verified' => true
                ]
                ]);
            $this->customerRepo->update([[
                'id' => $customer->getId(),
                'email' => $email
            ]], $context->getContext());
        } catch (ClientException $e) {
            return json_decode($e->getResponse()->getBody()->getContents());
        }
    }

    public function mapSubToCustomer($email, $sub,  $context)
    {
        $client = new Client();
        $customer = $this->getCustomerByEmail($email, $context);
        try {
            $temp_cf=$customer->getCustomFields();
            $temp_cf['sub'] = $sub;
            $this->customerRepo->update([[
                'id' => $customer->getId(),
                'customFields' => $temp_cf
            ]], $context->getContext());
        } catch (ClientException $e) {
            return json_decode($e->getResponse()->getBody()->getContents());
        }
    }

    public function checkCustomerNumber($user, $context) {
        $sub = $user['sub'];
        $customer = $this->getCustomerBySub($sub, $context);
        if (isset($user['customFields']['adressnummer'])) {
            $customerNumber = $customer->getCustomerNumber();
            $adrNr = $user['customFields']['adressnummer'];
            if ($customerNumber != $adrNr) {
                $this->customerRepo->update([
                    [
                        'id' => $customer->getId(),
                        'customerNumber' => $adrNr
                    ]
                ], $context->getContext());
            }
        }
        return null;
    }

    public function checkCustomerData($user, $context) {
        $customer = $this->getCustomerBySub($user['sub'], $context);
        if ($customer->getEmail() !== $user['email']) {
            $this->customerRepo->update([
                [
                    "id" => $customer->getId(),
                    "email" => $user['email']
                ]
            ], $context->getContext());
            $customer = $this->getCustomerBySub($user['sub'], $context);
        }
        $billingId = $customer->getDefaultBillingAddressId();
        $billing = $this->customerAddressRepo->search(new Criteria([$billingId]), $context->getContext())->first();
        $country = $this->getCountryId($user['customFields']['billing_address_country']);

        if (array_key_exists('company', $user['customFields'])) {
            $company = $user['customFields']['company'];
        } else {
            $company  = "";
        }

        $this->customerAddressRepo->update([
            [
                'id' => $billing->getId(),
                'street' => $user['customFields']['billing_address_street'],
                'city' => $user['customFields']['billing_address_city'],
                'zipcode' => $user['customFields']['billing_address_zipcode'],
                "countryId" => $country,
                "company" => $company,
            ]
        ], $context->getContext());
        
    }
    public function updateCustomerFromCidaas($user, $context) {
        $customer = $this->getCustomerBySub($user['sub'], $context);
        $salutationId =  $salutation = $this->getSalutationId($user['customFields']['salutation']);
        $this->customerRepo->update([
            [
                "id" => $customer->getId(),
                'firstName' =>$user['given_name'],
                'lastName' =>$user['family_name'],
                'salutationId' => $salutationId,
            ]
        ], $context->getContext());
    }

    public function checkWebshopId($user, $context) {
        $sub = $user['sub'];
        if (isset($user['customFields']['webshop_id'])) {
            file_put_contents('dumm.txt', '');
            return null;
        }
        $customer = $this->getCustomerBySub($sub, $context);
        $this->setWebShopId($customer->getId(), $sub);
    }

    public function checkCustomerGroups($user, $context) {
        $groups = [];
        $customer = $this->getCustomerBySub($user['sub'], $context);
        if (array_key_exists('groups', $user) && count($user['groups'])<2) {
            $stdGroup = $this->getGroupByName('Standard-Kundengruppe', $context);
            if($customer->getGroupId() !== $stdGroup->getCustomerGroupId()) {
                $this->customerRepo->update([
                    [
                        'id' => $customer->getId(),
                        'groupId' => $this->defaultGroup
                    ]
                ], $context->getContext());
            }
        }

        if (array_key_exists('groups', $user)) {
            foreach($user['groups'] as $g) {
                if ($g['groupId'] !== 'CIDAAS_USERS')
                    $groups[] = $g['groupId'];
            }
        }
        return;
    }

    public function getCustomerGroups(SalesChannelContext $context) {
        $cg = $this->customerGroupRepo->search(new Criteria(), $context->getContext());
        return $cg;
    }

    public function getMitgliederGroup(SalesChannelContext $context) {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter("name", "Mitglieder"));
        return $this->customerGroupRepo->search($criteria, $context->getContext())->first();
    }

    public function getMitarbeiterPromoGroup(SalesChannelContext $context) {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter("name", "MitarbeiterPromo"));
        return $this->customerGroupRepo->search($criteria, $context->getContext())->first();
    }
    
    public function getMitarbeiterGroup(SalesChannelContext $context) {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('name', 'Mitarbeiter'));
        return $this->customerGroupRepo->search($criteria, $context->getContext())->first();
    }

    /**
     * The original code received throws error as wrong table being used to fetch the customerGroupId, name is not a part of the table customer_group.
     * The name column is a part of the table customer_group_tranlsation where customer_group_id is a foreign key that is the pirmary key of the table customer_group.
     * Due to the above reason previous return statement is commented
     */
    public function getGroupByName($name, SalesChannelContext $context) {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('name', $name));
        // return $this->customerGroupRepo->search($criteria, $context->getContext())->first();
        return $this->customerGroupTranslationRepo->search($criteria, $context->getContext())->first();
    }

    public function validateToken($token) {
        $client = new Client();
        try {
            $response = $client->post($this->oAuthEndpoints->introspection_endpoint, [
                'form_params' => [
                    'token' => $token
                ]
            ]);
            $active = json_decode($response->getBody()->getContents())->active;
            return $active;
        } catch (ClientException $e) {
            return $false;
        }
    }

    // 'scopes' => "openid email profile"
    // private

    private function generateRandomString($length = 10) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    private function setWebShopId($id, $sub) {
        $token = $this->getAdminToken();
        $client = new Client();
        try {
            $resp = $client->put($this->cidaasUrl.'/users-srv/user/'.$sub, [
                'headers' => [
                    'Authorization' => 'Bearer '.$token->access_token
                ],
                'form_params' => [
                    'sub' => $sub,
                    'provider' => 'SELF',
                    'customFields' => [
                        'webshop_id' => $id
                    ]
                ]
                ]);
        } catch (ClientException $e) {
            return json_decode($e->getResponse()->getBody()->getContents());
        }
    }

    public function getAccessToken(String $code, String $url)
    {
        $client = new Client();
        $redirectUri = $url.'/cidaas/redirect';
        try {
            $response = $client->post($this->oAuthEndpoints->token_endpoint, [
                'form_params' => [
                    'grant_type' => 'authorization_code',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'code' => $code,
                    'redirect_uri' => $redirectUri
                ],
                'headers' => [
                    'content_type' => 'application/json'
                ]
            ]);
        } 
        catch (ClientException $e) {
            $msg = \json_decode($e->getResponse()->getBody()->getContents());
            return $msg;
        }
        return json_decode($response->getBody()->getContents(), true);
    }

    public function changePassword($newPassword, $confirmPassword, $oldPassword, $sub, $token) {
        $client = new Client();
        try {
            $response = $client->post($this->cidaasUrl.'/users-srv/changepassword', [
                'headers' => [
                    'authorization' => 'Bearer '.$token
                ],
                'form_params' => [
                    'sub' => $sub,
                    'new_password' => $newPassword,
                    'confirm_password' => $confirmPassword,
                    'old_password' => $oldPassword
                ]
                ]);
            return json_decode($response->getBody()->getContents());
        } catch (ClientException $e) {
            return json_decode($e->getResponse()->getBody()->getContents());
        }
    }

    public function updateProfile($firstName, $lastName, $salutationId, $sub, $context) {
        $client = new Client();
        $customer = $this->getCustomerBySub($sub, $context);
        $adminToken = $this->getAdminToken();
        $queryBuilder = $this->connection->createQueryBuilder();
        $tmp_id=Uuid::fromHexToBytes($salutationId);
        $queryBuilder->select('salutation_key')
            ->from('salutation')
            ->where('id="'.$tmp_id.'"');
            $salutationKey = $queryBuilder->executeQuery()->fetchFirstColumn();
        try {
            $response = $client->put($this->cidaasUrl.'/users-srv/user/'.$sub, [
                'headers' => [
                    'authorization' => 'Bearer '.$adminToken->access_token
                ],
                'form_params' => [
                    'given_name' => $firstName,
                    'family_name' => $lastName,
                    'customFields' => [
                        'salutation' => $salutationKey ? $salutationKey : 'not_specified'
                    ],
                    'sub' => $sub,
                    'provider' => 'self'
                ]
                ]);
            $this->customerRepo->update([[
                'id' => $customer->getId(),
                'firstName' => $firstName,
                'lastName' => $lastName,
                'salutationId' => $salutationId
            ]], $context->getContext());
            return json_decode($response->getBody()->getContents());
        } catch (ClientException $e) {
            return json_decode($e->getResponse()->getBody()->getContents());
        }
    }

    private function getCountryId($countryVal) {
        $queryBuilder = $this->connection->createQueryBuilder();
        $queryBuilder->select('country_id')
            ->from('country_translation')
            ->where('name="'.$countryVal.'"');
        $country = $queryBuilder->execute()->fetchAll(FetchMode::COLUMN);
        if (!$country) {
            $queryBuilder = $this->connection->createQueryBuilder();
            $queryBuilder->select('id')
                ->from('country')
                ->where('iso="'.$countryVal.'"');
            $country = $queryBuilder->execute()->fetchAll(FetchMode::COLUMN);
        }
        if (!$country) {
            $queryBuilder = $this->connection->createQueryBuilder();
            $queryBuilder->select('id')
                ->from('country')
                ->where('iso="DE"');
            $country = $queryBuilder->execute()->fetchAll(FetchMode::COLUMN);
        }
        return Uuid::fromBytesToHex($country[0]);
    }

    private function getSalutationId($salutation) {
        $queryBuilder = $this->connection->createQueryBuilder();
        if ($salutation === null || $salutation === "") {
            $queryBuilder = $this->connection->createQueryBuilder();
            $queryBuilder->select('id')
                ->from('salutation')
                ->where('salutation_key="not_specified"');
            $salutation = $queryBuilder->execute()->fetchAll(FetchMode::COLUMN)[0];
            return Uuid::fromBytesToHex($salutation);
        }
        $queryBuilder->select('id')
            ->from('salutation')
            ->where('salutation_key="'. $salutation .'"');
        $salutation = $queryBuilder->execute()->fetchAll(FetchMode::COLUMN)[0];
        return Uuid::fromBytesToHex($salutation);
    }

    private function getAdminToken() {
        $client = new Client();
        $resp = $client->post($this->cidaasUrl.'/token-srv/token', [
            'form_params' => [
                "grant_type" =>  'client_credentials',
                'client_id' => $this->nonInteractiveClientId,
                'client_secret' => $this->nonInteractiveClientSecret
            ]
            ]);
        return json_decode($resp->getBody()->getContents());
    }

    private function getCountry(string $countryId){
        /**
         * @var CountryEntity|null $country
         */
        $country = $this->countryRepository->search(new Criteria([$countryId]), Context::createDefaultContext())->get($countryId);

        if (!$country instanceof CountryEntity) {
            throw new CountryNotFoundException($countryId);
        }
        return $country->name;
    }

    public function updateBillingAddress($address, $sub, $context) {
        $client = new Client();
        $customer = $this->getCustomerBySub($sub, $context);
        $adminToken = $this->getAdminToken();
        $street =  $address->get('street');
        $zipCode =  $address->get('zipcode');
        $company =  $address->get('company');
        $city =  $address->get('city');
        $countryId = $address->get('countryId');
        $country = $this->getCountry($countryId);
        $addressId =  $address->get('id');

        try {
            $response = $client->put($this->cidaasUrl.'/users-srv/user/'.$sub, [
                'headers' => [
                    'authorization' => 'Bearer '.$adminToken->access_token
                ],
                'form_params' => [
                    'customFields' => [
                        'billing_address_zipcode' => $zipCode ,
                        'billing_address_street' => $street,
                        'company' => $company,
                        'billing_address_city' => $city,
                        'billing_address_country' => strtolower($country)
                    ],
                    'sub' => $sub,
                    'provider' => 'self'
                ]
                ]);
             
                $this->customerAddressRepo->update([
                    [
                        'id' => $addressId,
                        'salutationId' => $address->get('salutationId'),
                        'firstName' => $address->get('firstName'),
                        'lastName' => $address->get('lastName'),
                        'street' => $address->get('street'),
                        'city' => $address->get('city'),
                        'zipcode' => $address->get('zipcode'),
                        'countryId' => $address->get('countryId'),
                        'countryStateId' => $address->get('countryStateId') ?: null,
                        'company' => $address->get('company'),
                        'department' => $address->get('department') ?: null,
                    ]
                ], $context->getContext());
            return json_decode($response->getBody()->getContents());
        } catch (ClientException $e) {
            return json_decode($e->getResponse()->getBody()->getContents());
        }
    }

    public function updateAddressToShopware($address, $context) {
        $addressId =  $address->get('id');
        $this->customerAddressRepo->update([
            [
                'id' => $addressId,
                'salutationId' => $address->get('salutationId'),
                'firstName' => $address->get('firstName'),
                'lastName' => $address->get('lastName'),
                'street' => $address->get('street'),
                'city' => $address->get('city'),
                'zipcode' => $address->get('zipcode'),
                'countryId' => $address->get('countryId'),
                'countryStateId' => $address->get('countryStateId') ?: null,
                'company' => $address->get('company'),
                'department' => $address->get('department') ?: null,
            ]
        ], $context->getContext());

    }
    
}