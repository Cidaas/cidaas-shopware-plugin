<?php declare(strict_types=1);

namespace Cidaas\OauthConnect\Controller;

use Shopware\Storefront\Controller\StorefrontController;
use Symfony\Component\Routing\Annotation\Route;
use Shopware\Core\Framework\Routing\Annotation\RouteScope;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\Checkout\Cart\LineItem\LineItem;
use Shopware\Core\Checkout\Cart\SalesChannel\CartService;
use Shopware\Core\Checkout\Customer\SalesChannel\AccountService;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractLogoutRoute;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractListAddressRoute;
use Shopware\Core\Framework\Validation\Exception\ConstraintViolationException;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use GuzzleHttp\Client;
use Cidaas\OauthConnect\Service\CidaasLoginService;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Checkout\Customer\Exception\AddressNotFoundException;
use Shopware\Core\Framework\Validation\DataBag\DataBag;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerAddress\CustomerAddressEntity;
use Cidaas\OauthConnect\Util\CidaasStruct;
use Shopware\Core\Framework\Uuid\Exception\InvalidUuidException;
use Shopware\Storefront\Page\Checkout\Register\CheckoutRegisterPageLoadedHook;
use Shopware\Storefront\Page\Checkout\Register\CheckoutRegisterPageLoader;
use Shopware\Core\Framework\Routing\RoutingException;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractRegisterRoute;
use Shopware\Storefront\Page\Address\AddressEditorModalStruct;
use Shopware\Storefront\Page\Address\Listing\AddressListingPageLoader;
use Shopware\Storefront\Page\Address\Listing\AddressBookWidgetLoadedHook;
use Shopware\Core\Framework\Feature;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractUpsertAddressRoute;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractChangeCustomerProfileRoute;

/**
 * @RouteScope(scopes={"storefront"})
 */

 class CidaasHelperController extends StorefrontController {

    private $loginService;
    private $cartService;
    private $logoutRoute;
    private $listAddressRoute;
    private const ADDRESS_TYPE_BILLING = 'billing';
    private const ADDRESS_TYPE_SHIPPING = 'shipping';

    private $state;
    private AddressListingPageLoader $addressListingPageLoader;
    private AbstractUpsertAddressRoute $updateAddressRoute;
    private AbstractChangeCustomerProfileRoute $updateCustomerProfileRoute;

    public function __construct(
        CidaasLoginService $loginService, 
        CartService $cartService,
        AbstractLogoutRoute $logoutRoute,
        AbstractListAddressRoute $listAddressRoute,
        AccountService $accountService,
        CheckoutRegisterPageLoader $registerPageLoader,
        AbstractRegisterRoute $registerRoute,
        AddressListingPageLoader $addressListingPageLoader,
        AbstractUpsertAddressRoute $updateAddressRoute,
        AbstractChangeCustomerProfileRoute $updateCustomerProfileRoute
        ) {
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
        $this->loginService = $loginService;
        $this->cartService = $cartService;
        $this->logoutRoute = $logoutRoute;
        $this->listAddressRoute = $listAddressRoute;
        $this->accountService = $accountService;
        $this->registerPageLoader = $registerPageLoader;
        $this->registerRoute = $registerRoute;
        $this->addressListingPageLoader = $addressListingPageLoader;
        $this->updateAddressRoute = $updateAddressRoute;
        $this->updateCustomerProfileRoute = $updateCustomerProfileRoute;

    }

    // Redirect all account login stuff

    /**
     * @Route("/account/login", name="frontend.account.login.page")
     */
    public function loginRedirect(Request $request): Response
    {
        if ($request->get('redirectTo')) {
            if ($request->get('redirectParameters')) {
                return $this->forwardToRoute('cidaas.login', ['redirectTo' => $request->get('redirectTo'), 'redirectParameters' => json_decode($request->get('redirectParameters'))]);
            } else {
                return $this->forwardToRoute('cidaas.login', ['redirectTo' => $request->Get('redirectTo')]);
            }
            return $this->redirectTo('cidaas.login');
        }
        return $this->forwardToRoute('frontend.home.page');
    }

    /**
     * @Route("/cidaas/redirect", name="cidaas.redirect", options={"seo"="false"}, methods={"GET"})
     */
    public function cidaasRedirect(Request $request, SalesChannelContext $context)
    {
        $code = $request->query->get('code');
        $state = $request->query->get('state');
        $sess = $request->getSession()->get('state');

        // get storfront url
        $baseUrl = $request->get('sw-storefront-url');

        if ($state === $sess) {
            $token = $this->loginService->getCidaasAccessToken($code, $baseUrl);
            if (is_array($token)) {
                if (isset($token['sub'])) {

                    $_SESSION['accessToken'] = $token[ 'access_token' ];
                    if(isset($token[ 'refresh_token' ])) {
                        $_SESSION['refreshToken'] = $token[ 'refresh_token' ];
                    }
                    
                    $request->getSession()->set( 'sub', $token[ 'sub' ] );

                    $user = $this->loginService->getAccountFromCidaas($token['access_token']);
                    $temp = $this->loginService->customerExistsByEmail($user['email'], $context);
                    if (!$this->loginService->customerExistsBySub($token['sub'], $context) && !$this->loginService->customerExistsByEmail($user['email'], $context)['exists']) {
                        try {
                            if ($this->hasRequiredUserData($user)) {
                                // User has all the required data
                                $this->loginService->registerExistingUser( $user, $context, $baseUrl );
                                $this->loginService->checkCustomerGroups( $user, $context );
                                } else {
                                    return $this->redirectToRoute( 'cidaas.register.additional.page' );
                                }
                            if ($request->getSession()->get('redirect_to')) {
                                $target = $request->getSession()->get('redirect_to');
                                $request->getSession()->remove('redirect_to');
                                return $this->forwardToRoute($target);
                            }
                            return $this->forwardToRoute('frontend.home.page');
                        } catch (ConstraintViolationException $formViolations) {
                            $err = $formViolations->getMessage();
                            $this->addFlash('danger', 'Error: '. $err);
                            return $this->forwardToRoute('frontend.home.page', [
                                'loginError'=>true,
                                'errorSnippet'=>$err ?? null
                            ]);
                        }
                    }
                    if (!$this->loginService->customerExistsBySub($token['sub'], $context) && $this->loginService->customerExistsByEmail($user['email'], $context)['exists']) {
                        $this->loginService->mapSubToCustomer($user['email'], $token['sub'], $context);
                    }
                    $this->loginService->checkCustomerGroups($user, $context);
                    $this->loginService->checkCustomerNumber($user, $context);
                    $this->loginService->checkWebshopId( $user,$token[ 'access_token' ], $context );
                    $this->loginService->checkCustomerData($user, $context);
                    $this->loginService->updateCustomerFromCidaas($user, $context);
                    $response = $this->loginService->loginBySub($token['sub'], $context);
                    $request->getSession()->set('sub', $token['sub']);
                    $token2 = $response->getToken();
                    $this->addCartErrors($this->cartService->getCart($token2, $context));
                    if ($request->getSession()->get('redirect_to')) {
                        $target = $request->getSession()->get('redirect_to');
                        $request->getSession()->remove('redirect_to');
                        if ($request->getSession()->get('redirectParameters')) {
                            $redirectParameters = $request->getSession()->get('redirectParameters');
                            $request->getSession()->remove('redirectParameters');
                            return $this->forwardToRoute($target, [], json_decode(json_encode($redirectParameters), true));
                        }
                        return $this->forwardToRoute($target);
                    }
                    $this->addFlash('success', 'Login Erfolgreich');
                    return $this->forwardToRoute('frontend.home.page');
                }
            } else if (is_object($token)) {
                if (isset($token->sub)) {

                    $_SESSION['accessToken'] = $token->access_token;
                    if(isset($token->refresh_token)) {
                        $_SESSION['refreshToken'] = $token->refresh_token;
                    }

                    $request->getSession()->set( 'sub', $token->sub );

                    $user = $this->loginService->getAccountFromCidaas($token->access_token);
                    if (!$this->loginService->customerExistsBySub($token->sub, $context) && !$this->loginService->customerExistsByEmail($user['email'], $context)['exists']) {
                        try {

                            if ($this->hasRequiredUserData($user)) {
                                // User has all the required data
                                $this->loginService->registerExistingUser( $user, $context, $baseUrl );
                                $this->loginService->checkCustomerGroups( $user, $context );
                                } else {
                                    return $this->redirectToRoute( 'cidaas.register.additional.page' );
                                }
                            if ($request->getSession()->get('redirect_to')) {
                                $target = $request->getSession()->get('redirect_to');
                                $request->getSession()->remove('redirect_to');
                                return $this->forwardToRoute($target);
                            }
                            return $this->forwardToRoute('frontend.home.page');
                        } catch (ConstraintViolationException $formViolations) {
                            $err = $formViolations->getMessage();
                            $this->addFlash('danger', 'Error: '. $err);
                            return $this->forwardToRoute('frontend.home.page', [
                                'loginError'=>true,
                                'errorSnippet'=>$err ?? null
                            ]);
                        }
                    }
                    if (!$this->loginService->customerExistsBySub($token->sub, $context) && $this->loginService->customerExistsByEmail($user['email'], $context)['exists']) {
                        $this->loginService->mapSubToCustomer($user['email'], $token->sub, $context);
                    }
                    $this->loginService->checkCustomerGroups($user, $context);
                    $this->loginService->checkCustomerNumber($user, $context);
                     $this->loginService->checkWebshopId( $user, $token->access_token, $context );
                    $this->loginService->checkCustomerData($user, $context);
                    $this->loginService->updateCustomerFromCidaas($user, $context);
                    $response = $this->loginService->loginBySub($token->sub, $context);
                    $request->getSession()->set('sub', $token->sub);
                    $token2 = $response->getToken();
                    $this->addCartErrors($this->cartService->getCart($token2, $context));
                    if ($request->getSession()->get('redirect_to')) {
                        $target = $request->getSession()->get('redirect_to');
                        $request->getSession()->remove('redirect_to');
                        if ($request->getSession()->get('redirectParameters')) {
                            $redirectParameters = $request->getSession()->get('redirectParameters');
                            $request->getSession()->remove('redirectParameters');
                            return $this->forwardToRoute($target, [], json_decode(json_encode($redirectParameters), true));
                        }
                        return $this->forwardToRoute($target);
                    }
                    $this->addFlash('success', 'Login Erfolgreich');
                    return $this->forwardToRoute('frontend.home.page');
                }
            }
            
            $this->addFlash('error', 'Das sollte nicht passieren, Entschuldigung');
            return $this->forwardToRoute('frontend.home.page');
        }
        $this->addFlash('error', 'Fehler bei der Anmeldung/Registrierung! Entschuldigung!');
        return $this->forwardToRoute('frontend.home.page');
    }

    public function hasRequiredUserData($user) {
        // Check if all required fields are present
        if (isset($user['given_name']) &&
            isset($user['family_name']) &&
            isset($user['email']) &&
            isset($user['customFields']['billing_address_street']) &&
            isset($user['customFields']['billing_address_zipcode']) &&
            isset($user['customFields']['billing_address_city'])) {
            return true; // All required data is present
        }
        return false; // At least one required field is missing
    }

    /**
     * @Route("/account/logout", name="frontend.account.logout.page", methods={"GET"})
     */
    public function logout(Request $request, SalesChannelContext $context, RequestDataBag $dataBag): Response
    {
        if ($context->getCustomer() === null) {
            return $this->redirectToRoute('frontend.account.login.page');
        }
        try {
            if(isset($_SESSION['accessToken'])){
                $this->loginService->endSession($_SESSION['accessToken']);
            }
            $this->logoutRoute->logout($context, $dataBag);
            $salesChannelId = $context->getSalesChannel()->getId();
            if ($request->hasSession() && $this->loginService->getSysConfig('core.loginRegistration.invalidateSessionOnLogOut', $salesChannelId)) {
               $request->getSession()->invalidate();
            }
            $request->getSession()->remove('state');
            $request->getSession()->remove('sub');
            if(isset($_SESSION['accessToken'])) {
                unset($_SESSION['accessToken']);
            }
            if(isset($_SESSION['refreshToken'])) {
                unset($_SESSION['refreshToken']);
            }
            session_destroy();
            
            $this->addFlash(self::SUCCESS, $this->trans('account.logoutSucceeded'));
            $parameters = [];
        } catch (ConstraintViolationException $formViolations) {
            $parameters = ['formViolations' => $formViolations];
        }

        return $this->redirectToRoute('frontend.account.login.page', $parameters);
    }

    /**
     * @Route("/cidaas/exists", name="cidaas.exists", methods={"POST"}, options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function exists(Request $request, SalesChannelContext $context): Response
    {
        $email = $request->get('email');
        $exists = $this->loginService->customerExistsByEmail($email, $context);
        return $this->json($exists);
    }

    /**
     * @Route("/cidaas/authuri/{email}", name="cidaas.authuri", methods={"GET"}, options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function authuri(Request $request, $email): Response
    {
        if ($request->getSession()->get('state')) {
            $state = $request->getSession()->get('state');
        }
        $authUri =  $this->loginService->getAuthorizationUri($state, $request->get('sw-sales-channel-absolute-base-url', $email));
        return $this->json(array(
            'authUri' => $authUri
        ));
    }

    /**
     * @Route("/cidaas/lastlogin/{customerId}", name="cidaas.lastlogin", methods={"GET"}, options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function lastLogin(Request $request, SalesChannelContext $context, $customerId): Response
    {
        $lastLogin = $this->loginService->getLastLogin($customerId, $context);
        return $this->json(array(
            "lastLogin"=> $lastLogin
        ));
    }

    /**
     * @Route("/cidaas/login", name="cidaas.login", methods={"GET"}, options={"seo"="false"})
     */
    public function cidaasLogin(Request $request, SalesChannelContext $context): Response
    {
        $baseURL = $this->loginService->createBaseURL($request);
        $locale = $request->query->get('_locale');
        $localeCode = explode('-', $locale)[0];


        if ($request->query->get('redirect_to')) {
            $request->getSession()->set('redirect_to', $request->query->get('redirect_to'));
        }
        if ($request->get('redirectTo')) {
            $request->getSession()->set('redirect_to', $request->get('redirectTo'));
        }
        if ($request->get("redirectParameters")) {
            $request->getSession()->set('redirectParameters', $request->get('redirectParameters'));
        }
        $state = Uuid::randomHex();
        if ($request->getSession()->get('state')) {
            $state = $request->getSession()->get('state');
        } else {
            $request->getSession()->set('state', $state);
        }
        $red = $this->loginService->getAuthorizationUri($state, $baseURL, $localeCode);
        return new RedirectResponse($red);
    }

    /**
     * @Route("/cidaas/register", name="cidaas.register", methods={"GET"}, options={"seo"="false"})
     */
    public function cidaasRegister(Request $request, SalesChannelContext $context): Response
    {
        $baseURL = $this->loginService->createBaseURL($request);
        $locale = $request->query->get('_locale');
        $localeCode = explode('-', $locale)[0];

        $state = Uuid::randomHex();
        $request->getSession()->set('state', $state);
        if ($request->query->get('userIdHint')) {
            $userIdHint = $request->query->get('userIdHint');
            $type = $request->query->get('type');
            return new RedirectResponse($this->loginService->getRegisterUri($state,  $baseURL, $locale, $userIdHint, $type));
        }
        return new RedirectResponse($this->loginService->getRegisterUri($state,  $baseURL, $localeCode));
    }


    /**
     * @Route("/cidaas/changepassword", name="cidaas.changepassword", methods={"GET", "POST"}, options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function changePassword(Request $request, SalesChannelContext $context): Response
    {
        $sub = $request->getSession()->get('sub');

        $accessTokenObj =$this->loginService->getAccessToken();

        if(!$accessTokenObj->success){
            return  $this->redirectToRoute( 'frontend.account.logout.page' );
        }
        $accessToken = $accessTokenObj->token;

        $newPassword = $request->get('newPassword');
        $confirmPassword = $request->get('confirmPassword');
        $oldPassword = $request->get('oldPassword');

        $res = $this->loginService->changePassword($newPassword, $confirmPassword, $oldPassword, $sub, $accessToken);
        $this->addFlash('success', 'Passwort erfolgreich geändert');
        return $this->json($res);
    }

    /**
     * @Route("/cidaas/emailform", name="cidaas.emailform", methods={"POST"}, options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function emailForm(Request $request, SalesChannelContext $context): Response
    {
        $sub = $request->getSession()->get('sub');
        $email = $request->get('email');

        $accessTokenObj =$this->loginService->getAccessToken();

        if(!$accessTokenObj->success){
            return  $this->redirectToRoute( 'frontend.account.logout.page' );
        }
        $accessToken = $accessTokenObj->token;

        $this->loginService->changeEmail($email, $sub, $accessToken, $context);
        $this->addFlash('success', 'E-Mail Adresse geändert');
        return $this->json(
            array()
        );
    }

     /**
     * @Route("/cidaas/update-profile", name="frontend.account.profile.save", methods={"POST"}, options={"seo"="false"}, defaults={"_loginRequired"=true})
     */
    public function updateProfile(Request $request, RequestDataBag $data, SalesChannelContext $context, CustomerEntity $customer): Response
    {
        $sub = $request->getSession()->get('sub');
        $firstName = $request->get('firstName');
        $lastName = $request->get('lastName');
        $salutationId = $request->get('salutationId');

        $accessTokenObj =$this->loginService->getAccessToken();

        if(!$accessTokenObj->success){
            return  $this->redirectToRoute( 'frontend.account.logout.page' );
        }
        $accessToken = $accessTokenObj->token;

        $res = $this->loginService->updateProfile($firstName, $lastName, $salutationId, $sub, $accessToken, $context);
        if($res) {
              // Assuming $object is your stdClass object
                $responseData = json_decode(json_encode($res), true);
                 // Key exists in the array
                if(array_key_exists('success', $responseData)){
                  if($responseData['success'] === true){
                     $this->updateCustomerProfileRoute->change($data, $context, $customer);
                     $this->addFlash('success', 'Successfully updated profile');
                  } elseif ($responseData['success'] === false){
                    if (array_key_exists('error', $responseData)) {
                            // Handle error data
                            // Extract error details
                            $error = $responseData['error']['error'];
                            $this->addFlash('danger', 'Failed to update profile: '.$error);
                        } else {
                            // No error information available
                            error_log(json_encode($responseData));
                            $this->addFlash('danger', 'Failed to update profile for unknown reason. Please check error log for more details.');
                        }
                  } else {
                      $this->addFlash('danger', 'Failed to update profile for unknown reason.');
                  }
                } else {
                    // Key does not exist in the array
                    $this->addFlash('danger', 'Failed to update profile for unknown reason.');
                }
        } else {
            $this->addFlash('danger', 'Failed to update profile for unknown reason.');
        }
        return $this->redirectToRoute('frontend.account.profile.page');
    }

    /**
     * @Route("/cidaas/url", name="cidaas.url", methods={"GET"}, options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function getUrl(Request $request): Response
    {
        return $this->json(array(
            "url" => $this->loginService->getCidaasUrl()
        ));
    }

    /**
     * @Route("/cidaas/generate", name="cidaas.generate", methods={"POST"}, options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function generateRequest(Request $request, SalesChannelContext $context): Response
    {
        $clientId = $this->loginService->getSysConfig('CidaasHelper.config.clientId');
        $url = $request->get('sw-sales-channel-absolute-base-url').'/cidaas/redirect';
        $state = $request->getSession()->get('state');
        return $this->json(
            array(
                "clientId" => $clientId,
                "url" => $url,
                "state" => $state
            )
        );
    }

     /**
     * @Route("/checkout/register", name="frontend.checkout.register.page", options={"seo"="false"}, methods={"GET"})
     */
    public function checkoutRegisterPage(Request $request, RequestDataBag $data, SalesChannelContext $context): Response
    {
        /** @var string $redirect */
        $redirect = $request->get('redirectTo', 'frontend.checkout.confirm.page');
        $errorRoute = $request->attributes->get('_route');


        if ($context->getCustomer()) {
            return $this->redirectToRoute($redirect);
        }

        if ($this->cartService->getCart($context->getToken(), $context)->getLineItems()->count() === 0) {
            return $this->redirectToRoute('frontend.checkout.cart.page');
        }

        $page = $this->registerPageLoader->load($request, $context);

        $this->hook(new CheckoutRegisterPageLoadedHook($page, $context));

        return  $this->renderStorefront("@CidaasOauthConnect/storefront/page/guest.html.twig",
           ['redirectTo' => $redirect, 'errorRoute' => $errorRoute, 'page' => $page, 'data' => $data]
       );
    }

    /**
     * @Route("/cidaas/update-address", name="frontend.account.address.edit.save", options={"seo"="false"}, methods={"POST"}, defaults={"_loginRequired"=true})
     */
    public function billingAddressUpdate(Request $request,RequestDataBag $data, SalesChannelContext $context,  CustomerEntity $customer): Response {
        
        $addressData = $this->convertToCustomerAddressEntity($data);
        $sub = $request->getSession()->get('sub');
        $activeBillingAddress = $customer->getActiveBillingAddress();
        $activeBillingAddressId = $activeBillingAddress->get('id');
        $addressId =  $addressData->get('id');

        if($addressId === $activeBillingAddressId){
            $this->updateBillingAddressToCidaas($addressData, $sub, $context);
        } else {
            $this->loginService->updateAddressToShopware($addressData, $context);
        }
        return $this->redirectToRoute('frontend.account.address.page');
    }

     /**
     * @Route("/cidaas/address/default-{type}/{addressId}", name="frontend.account.address.set-default-address", methods={"POST"}, defaults={"_loginRequired"=true})
     */
    public function switchDefaultAddresses(Request $request, string $type, string $addressId, SalesChannelContext $context, CustomerEntity $customer): RedirectResponse {
        if (!Uuid::isValid($addressId)) {
            throw new InvalidUuidException($addressId);
        }
        try {
            if ($type === self::ADDRESS_TYPE_SHIPPING) {
                $this->accountService->setDefaultShippingAddress($addressId, $context, $customer);
            } elseif ($type === self::ADDRESS_TYPE_BILLING) {
                $sub = $request->getSession()->get('sub');
                $address = $this->getById($addressId, $context, $customer);
                $this->updateBillingAddressToCidaas($address, $sub, $context);
                $this->accountService->setDefaultBillingAddress($addressId, $context, $customer);
            } else {
                $this->addFlash('danger', 'Address not found');
            }
        } catch (AddressNotFoundException $exception) {
            $this->addFlash('danger', 'Address not found');
        }
        return $this->redirectToRoute('frontend.account.address.page');
    }

    private function updateBillingAddressToCidaas(CustomerAddressEntity $address, string $sub, SalesChannelContext $context){

        $accessTokenObj =$this->loginService->getAccessToken();

        if(!$accessTokenObj->success){
            return  $this->forwardToRoute( 'frontend.account.logout.page' );
        }
        $accessToken = $accessTokenObj->token;

        $res = $this->loginService->updateBillingAddress($address, $sub,  $accessToken,  $context);
        if($res) {
            // Assuming $object is your stdClass object
              $responseData = json_decode(json_encode($res), true);
               // Key exists in the array
              if(array_key_exists('success', $responseData)){
                if($responseData['success'] === true){
                   $this->addFlash('success', 'Successfully updated Billing address');
                } elseif ($responseData['success'] === false){
                  if (array_key_exists('error', $responseData)) {
                          $error = $responseData['error']['error'];
                          $this->addFlash('danger', 'Failed to update billing address: '.$error);
                      } else {
                          // No error information available
                          error_log(json_encode($responseData));
                          $this->addFlash('danger', 'Failed to update billing address for unknown reason. Please check error log for more details.');
                      }
                } else {
                    $this->addFlash('danger', 'Failed to update billing address for unknown reason.');
                }
              } else {
                  // Key does not exist in the array
                  $this->addFlash('danger', 'Failed to update billing address for unknown reason.');
              }
      } else {
          $this->addFlash('danger', 'Failed to update billing address for unknown reason.');
      }
    }



    private function getById(string $addressId, SalesChannelContext $context, CustomerEntity $customer): CustomerAddressEntity {
        if (!Uuid::isValid($addressId)) {
            throw new InvalidUuidException($addressId);
        }
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('id', $addressId));
        $criteria->addFilter(new EqualsFilter('customerId', $customer->getId()));
        $address = $this->listAddressRoute->load($criteria, $context, $customer)->getAddressCollection()->get($addressId);
        if (!$address) {
            throw CustomerException::addressNotFound($addressId);
        }
        return $address;
    }

    public function convertToCustomerAddressEntity(RequestDataBag $data): CustomerAddressEntity {
         /** @var RequestDataBag $address */

        $address = $data->get('address');
        $addressArray = [
            'id' => $address->get('id'),
            'salutationId' => $address->get('salutationId'),
            'firstName' => $address->get('firstName'),
            'lastName' => $address->get('lastName'),
            'street' => $address->get('street'),
            'city' => $address->get('city'),
            'zipcode' => $address->get('zipcode'),
            'countryId' => $address->get('countryId'),
            'countryStateId' => $address->get('countryStateId'),
            'company' => $address->get('company'),
            'department' => $address->get('department')
        ];

        // Create a new CustomerAddressEntity instance
        $addressEntity = new CustomerAddressEntity();
        $addressEntity->assign($addressArray);

        return $addressEntity;
    }

    /**
     * @Route("/guest/register", name="cidaas.guest.register.page", options={"seo"="false"}, methods={"GET"})
     */
    public function guestRegisterPage(Request $request, RequestDataBag $data, SalesChannelContext $context): Response
    {
         /** @var string $redirect */
         $redirect = $request->get('redirectTo', 'frontend.checkout.confirm.page');
         $errorRoute = $request->attributes->get('_route');
 
         if ($context->getCustomer()) {
             return $this->redirectToRoute($redirect);
         }
 
         if ($this->cartService->getCart($context->getToken(), $context)->getLineItems()->count() === 0) {
             return $this->redirectToRoute('frontend.checkout.cart.page');
         }
 
         $page = $this->registerPageLoader->load($request, $context);
 
         $this->hook(new CheckoutRegisterPageLoadedHook($page, $context));
 
         return $this->renderStorefront(
            '@Storefront/storefront/page/checkout/address/index.html.twig',
            ['redirectTo' => $redirect, 'errorRoute' => $errorRoute, 'page' => $page, 'data' => $data]
        );
    }

     /**
     * @Route("/account/register", name="frontend.account.register.save", methods={"POST"}, defaults={"_captcha"=true})
     */
    public function register(Request $request, RequestDataBag $data, SalesChannelContext $context): Response
    {
        if ($context->getCustomer()) {
            return $this->redirectToRoute('frontend.account.home.page');
        }

        try {
            if (!$data->has('differentShippingAddress')) {
                $data->remove('shippingAddress');
            }

            $data->set('storefrontUrl', $this->loginService->getConfirmUrl($context, $request));

            $data = $this->loginService->prepareAffiliateTracking($data, $request->getSession());

            $data->set('guest', true);

            $this->registerRoute->register(
                $data->toRequestDataBag(),
                $context,
                false,
                $this->loginService->getAdditionalRegisterValidationDefinitions($data, $context)
            );
        } catch (ConstraintViolationException $formViolations) {
            if (!$request->request->has('errorRoute')) {
                throw RoutingException::missingRequestParameter('errorRoute');
            }

            if (empty($request->request->get('errorRoute'))) {
                $request->request->set('errorRoute', 'frontend.account.register.page');
            }

            $params = $this->loginService->decodeParam($request, 'errorParameters');

            // this is to show the correct form because we have different usecases (account/register||checkout/register)
            return $this->forwardToRoute($request->get('errorRoute'), ['formViolations' => $formViolations], $params);
        }

        if ($this->loginService->isDoubleOptIn($data, $context)) {
            return $this->redirectToRoute('frontend.account.register.page');
        }

        return $this->createActionResponse($request);
    }

    public  function createActionResponse(Request $request): Response
    {
        if ($request->get('redirectTo') || $request->get('redirectTo') === '') {
            $params = $this->decodeParam($request, 'redirectParameters');

            $redirectTo = $request->get('redirectTo');

            if ($redirectTo) {
                return $this->redirectToRoute($redirectTo, $params);
            }

            return $this->redirectToRoute('frontend.home.page', $params);
        }

        if ($request->get('forwardTo')) {
            $params = $this->decodeParam($request, 'forwardParameters');

            return $this->forwardToRoute($request->get('forwardTo'), [], $params);
        }

        return new Response();
    }

    /**
    * @Route("/widgets/account/address-book", name="frontend.account.addressbook", options={"seo"=true}, methods={"POST"}, defaults={"XmlHttpRequest"=true, "_loginRequired"=true, "_loginRequiredAllowGuest"=true})
    */
    public function addressBook(Request $request, RequestDataBag $dataBag, SalesChannelContext $context, CustomerEntity $customer): Response
    {
        $viewData = new AddressEditorModalStruct();
        $params = [];

        try {
            $this->handleChangeableAddresses($viewData, $dataBag, $context, $customer);
            $this->handleAddressCreation($viewData, $dataBag, $context, $customer);
            $this->handleAddressSelection($viewData, $dataBag, $context, $customer);

            $page = $this->addressListingPageLoader->load($request, $context, $customer);

            $this->hook(new AddressBookWidgetLoadedHook($page, $context));

            $viewData->setPage($page);
            if (Feature::isActive('FEATURE_NEXT_15957')) {
                $this->handleCustomerVatIds($dataBag, $context, $customer);
            }
        } catch (ConstraintViolationException $formViolations) {
            $params['formViolations'] = $formViolations;
            $params['postedData'] = $dataBag->get('address');
        } catch (\Exception $exception) {
            $viewData->setSuccess(false);
            $viewData->setMessages([
                'type' => self::DANGER,
                'text' => $this->trans('error.message-default'),
            ]);
        }

        if ($request->get('redirectTo') || $request->get('forwardTo')) {
            return $this->createActionResponse($request);
        }
        $params = array_merge($params, $viewData->getVars());

        $response = $this->renderStorefront(
            '@Storefront/storefront/component/address/address-editor-modal.html.twig',
            $params
        );

        $response->headers->set('x-robots-tag', 'noindex');

        return $response;
    }

    private function handleAddressCreation(
        AddressEditorModalStruct $viewData,
        RequestDataBag $dataBag,
        SalesChannelContext $context,
        CustomerEntity $customer
    ): void {
        /** @var DataBag|null $addressData */
        $addressData = $dataBag->get('address');

        if ($addressData === null) {
            return;
        }

        $response = $this->updateAddressRoute->upsert(
            $addressData->get('id'),
            $addressData->toRequestDataBag(),
            $context,
            $customer
        );

        $addressId = $response->getAddress()->getId();

        $addressType = null;

        if ($viewData->isChangeBilling()) {
            $addressType = self::ADDRESS_TYPE_BILLING;
        } elseif ($viewData->isChangeShipping()) {
            $addressType = self::ADDRESS_TYPE_SHIPPING;
        }

        // prepare data to set newly created address as customers default
        if ($addressType) {
            $dataBag->set('selectAddress', new RequestDataBag([
                'id' => $addressId,
                'type' => $addressType,
            ]));
        }

        $viewData->setAddressId($addressId);
        $viewData->setSuccess(true);
        $viewData->setMessages(['type' => 'success', 'text' => $this->trans('account.addressSaved')]);
    }

    private function handleChangeableAddresses(
        AddressEditorModalStruct $viewData,
        RequestDataBag $dataBag,
        SalesChannelContext $context,
        CustomerEntity $customer
    ): void {
        $changeableAddresses = $dataBag->get('changeableAddresses');

        if ($changeableAddresses === null) {
            return;
        }

        $viewData->setChangeShipping((bool) $changeableAddresses->get('changeShipping'));
        $viewData->setChangeBilling((bool) $changeableAddresses->get('changeBilling'));

        $addressId = $dataBag->get('id');

        if (!$addressId) {
            return;
        }

        $viewData->setAddress($this->getById($addressId, $context, $customer));
    }

    /**
     * @throws CustomerNotLoggedInException
     * @throws InvalidUuidException
     */
    private function handleAddressSelection(
        AddressEditorModalStruct $viewData,
        RequestDataBag $dataBag,
        SalesChannelContext $context,
        CustomerEntity $customer
    ): void {
        $selectedAddress = $dataBag->get('selectAddress');

        if ($selectedAddress === null) {
            return;
        }

        $addressType = $selectedAddress->get('type');
        $addressId = $selectedAddress->get('id');

        if (!Uuid::isValid($addressId)) {
            throw new InvalidUuidException($addressId);
        }

        $success = true;

        try {
            if ($addressType === self::ADDRESS_TYPE_SHIPPING) {
                $address = $this->getById($addressId, $context, $customer);
                $customer->setDefaultShippingAddress($address);
                $this->accountService->setDefaultShippingAddress($addressId, $context, $customer);
            } elseif ($addressType === self::ADDRESS_TYPE_BILLING) {
                $address = $this->getById($addressId, $context, $customer);
                $customer->setDefaultBillingAddress($address);
                $this->accountService->setDefaultBillingAddress($addressId, $context, $customer);
                $sub = $this->loginService->getSubFromCustomFields( $customer);
                if ($sub) {
                    $this->updateBillingAddressToCidaas($address, $sub, $context);
                }

            } else {
                $success = false;
            }
        } catch (AddressNotFoundException $exception) {
            $success = false;
        }

        if ($success) {
            $this->addFlash(self::SUCCESS, $this->trans('account.addressDefaultChanged'));
        } else {
            $this->addFlash(self::DANGER, $this->trans('account.addressDefaultNotChanged'));
        }

        $viewData->setSuccess($success);
    }

    private function handleCustomerVatIds(RequestDataBag $dataBag, SalesChannelContext $context, CustomerEntity $customer): void
    {
        if (!$dataBag->has('vatIds')) {
            return;
        }

        $newVatIds = $dataBag->get('vatIds')->all();
        $oldVatIds = $customer->getVatIds() ?? [];
        if (!array_diff($newVatIds, $oldVatIds) && !array_diff($oldVatIds, $newVatIds)) {
            return;
        }

        $dataCustomer = CustomerTransformer::transform($customer);
        $dataCustomer['vatIds'] = $newVatIds;
        $dataCustomer['accountType'] = $customer->getCompany() === null ? CustomerEntity::ACCOUNT_TYPE_PRIVATE : CustomerEntity::ACCOUNT_TYPE_BUSINESS;

        $newDataBag = new RequestDataBag($dataCustomer);

        $this->updateCustomerProfileRoute->change($newDataBag, $context, $customer);
    }

     /**
     * @Route("/register/user/additionalInfo", name="cidaas.register.additional.page", options={"seo"="false"}, methods={"GET"})
     */
    public function registerAdditionalPage(Request $request, RequestDataBag $data, SalesChannelContext $context): Response
    {
        /** @var string $redirect */
        $redirect = $request->get('redirectTo', 'frontend.account.home.page');
        $errorRoute = $request->attributes->get('_route');
 
        if ($context->getCustomer()) {
            return $this->redirectToRoute($redirect);
        }

        $page = $this->registerPageLoader->load($request, $context);
 
        $this->hook(new CheckoutRegisterPageLoadedHook($page, $context));

        $accessTokenObj =$this->loginService->getAccessToken();

        if(!$accessTokenObj->success){
            return  $this->redirectToRoute( 'cidaas.register.additional.cancel' );
        }
        $accessToken = $accessTokenObj->token;

        $user = $this->loginService->getAccountFromCidaas( $accessToken );

        // Assuming $data is an instance of RequestDataBag
        $data = new RequestDataBag();

       // Define an array to map user keys to Shopware fields
        $userFieldsMap = [
            'given_name' => 'firstName',
            'family_name' => 'lastName',
            'email' => 'email',
            'customFields' => [
                'billing_address_country' => 'countryId',
                'billing_address_street' => 'street',
                'billing_address_city' => 'city',
                'billing_address_zipcode' => 'zipcode'
            ]
        ];

        // Loop through the user data and set the corresponding Shopware fields
        foreach ($userFieldsMap as $userKey => $shopwareField) {
            // Check if the user data contains the key
            if (isset($user[$userKey])) {
                // If the field is nested under 'customFields'
                if (is_array($shopwareField)) {
                    foreach ($shopwareField as $customKey => $customShopwareField) {
                        if (isset($user[$userKey][$customKey])) {
                            $data->set($customShopwareField, $user[$userKey][$customKey]);
                        }
                    }
                } else {
                    // Set the field in the data object
                    $data->set($shopwareField, $user[$userKey]);
                }
            }
        }
        return  $this->renderStorefront("@CidaasOauthConnect/storefront/cidaasauth/addressRegister.html.twig",
            ['redirectTo' => $redirect, 'errorRoute' => $errorRoute,'page' => $page,'data' => $data]
        );
    }

     /**
     * @Route("/save/user/additionalInfo", name="cidaas.register.additional.save", options={"seo"="false"}, methods={"POST"})
     */
    public function registerAdditionalSave(Request $request, RequestDataBag $formData, SalesChannelContext $context): Response
    {
        $accessTokenObj =$this->loginService->getAccessToken();

        if(!$accessTokenObj->success){
            return  $this->redirectToRoute( 'cidaas.register.additional.cancel' );
        }
        $accessToken = $accessTokenObj->token;

        $user = $this->loginService->getAccountFromCidaas( $accessToken );
         
        $url = $request->get( 'sw-sales-channel-absolute-base-url' );
        $sub = $request->getSession()->get( 'sub' );

        try {
            $this->loginService->registerAdditionalInfoForUser( $formData, $sub, $context, $request->get( 'sw-sales-channel-absolute-base-url' ) );
            $this->loginService->checkCustomerGroups( $user, $context );

            return $this->redirectToRoute( 'frontend.account.profile.page' );

        } catch ( ConstraintViolationException $formViolations ) {
            $err = $formViolations->getMessage();
            $this->addFlash( 'danger', 'Error: '. $err );
            return $this->forwardToRoute( 'frontend.home.page', [
                'loginError'=>true,
                'errorSnippet'=>$err ?? null
            ] );
        }

       return  $this->redirectToRoute( 'frontend.account.profile.page' );
    }


     /**
     * @Route("/cancel/user", name="cidaas.register.additional.cancel", options={"seo"="false"}, methods={"GET"})
     */
    public function cancel( Request $request, SalesChannelContext $context, RequestDataBag $dataBag ): Response {
        try {
            if(isset($_SESSION['accessToken'])){
                $this->loginService->endSession($_SESSION['accessToken']);
            }
            $this->logoutRoute->logout($context, $dataBag);
            $salesChannelId = $context->getSalesChannel()->getId();
            if ($request->hasSession() && $this->loginService->getSysConfig('core.loginRegistration.invalidateSessionOnLogOut', $salesChannelId)) {
               $request->getSession()->invalidate();
            }
            $request->getSession()->remove('state');
            $request->getSession()->remove('sub');
            if(isset($_SESSION['accessToken'])) {
                unset($_SESSION['accessToken']);
            }
            if(isset($_SESSION['refreshToken'])) {
                unset($_SESSION['refreshToken']);
            }
            session_destroy();
            $parameters = [];
        } catch ( ConstraintViolationException $formViolations ) {
            $parameters = [ 'formViolations' => $formViolations ];
        }

        return $this->redirectToRoute( 'frontend.account.login.page', $parameters );
    }
 }
