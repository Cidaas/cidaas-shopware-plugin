<?php declare (strict_types = 1);

namespace Cidaas\OauthConnect\Controller;

use Cidaas\OauthConnect\Service\CidaasLoginService;
use Shopware\Core\Checkout\Cart\SalesChannel\CartService;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractRegisterRoute;
use Shopware\Core\Framework\Routing\RoutingException;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\Framework\Validation\Exception\ConstraintViolationException;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Storefront\Controller\StorefrontController;
use Shopware\Storefront\Page\Checkout\Register\CheckoutRegisterPageLoadedHook;
use Shopware\Storefront\Page\Checkout\Register\CheckoutRegisterPageLoader;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route(defaults: ['_routeScope' => ['storefront']])]

class CidaasRegisterController extends StorefrontController
{

    public function __construct(
        private readonly CidaasLoginService $loginService,
        private readonly CartService $cartService,
        private readonly CheckoutRegisterPageLoader $registerPageLoader,
        private readonly AbstractRegisterRoute $registerRoute
    ) {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    #[Route(path: '/cidaas/register', name: 'cidaas.register', options: ['seo' => false], defaults: ['_noStore' => true], methods: ['GET'])]
    public function cidaasRegister(Request $request, SalesChannelContext $context): Response
    {
        $state = Uuid::randomHex();
        $request->getSession()->set('state', $state);
        if ($request->query->get('userIdHint')) {
            $userIdHint = $request->query->get('userIdHint');
            $type = $request->query->get('type');
            return new RedirectResponse($this->loginService->getRegisterUri($state, $request->get('sw-sales-channel-absolute-base-url'), $userIdHint, $type));
        }
        return new RedirectResponse($this->loginService->getRegisterUri($state, $request->get('sw-sales-channel-absolute-base-url')));
    }

    #[Route(path: '/register/user/additionalInfo', name: 'cidaas.register.additional.page', options: ['seo' => false], defaults: ['_noStore' => true], methods: ['GET'])]
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

        $token = $request->getSession()->get('access_token');

        // check token expiry and get renew access token
        $accessTokenObj = $this->loginService->getAccessToken();

        if (!$accessTokenObj->success) {
            return $this->forwardToRoute('frontend.account.logout.page');
        }
        $accessToken = $accessTokenObj->token;

        $user = $this->loginService->getAccountFromCidaas($accessToken);

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
                'billing_address_zipcode' => 'zipcode',
            ],
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
        return $this->renderStorefront("@CidaasOauthConnect/storefront/cidaasauth/addressRegister.html.twig",
            ['redirectTo' => $redirect, 'errorRoute' => $errorRoute, 'page' => $page, 'data' => $data]
        );
    }

    #[Route(path: '/save/user/additionalInfo', name: 'cidaas.register.additional.save', options: ['seo' => false], defaults: ['_noStore' => true], methods: ['POST'])]
    public function registerAdditionalSave(Request $request, RequestDataBag $formData, SalesChannelContext $context): Response
    {

        $accessTokenObj = $this->loginService->getAccessToken();

        if (!$accessTokenObj->success) {
            return $this->forwardToRoute('frontend.account.logout.page');
        }
        $accessToken = $accessTokenObj->token;

        $user = $this->loginService->getAccountFromCidaas($accessToken);

        $url = $request->get('sw-sales-channel-absolute-base-url');
        $sub = $request->getSession()->get('sub');

        try {
            $this->loginService->registerAdditionalInfoForUser($formData, $sub, $context, $request->get('sw-sales-channel-absolute-base-url'));
            $this->loginService->checkCustomerGroups($user, $context);

            return $this->redirectToRoute('frontend.account.profile.page');

        } catch (ConstraintViolationException $formViolations) {
            $err = $formViolations->getMessage();
            $this->addFlash('danger', 'Error: ' . $err);
            return $this->forwardToRoute('frontend.home.page', [
                'loginError' => true,
                'errorSnippet' => $err ?? null,
            ]);
        }

        return $this->redirectToRoute('frontend.account.profile.page');
    }

    #[Route(path: '/cancel/user', name: 'cidaas.register.additional.cancel', methods: ['GET'])]
    public function logout(Request $request, SalesChannelContext $context, RequestDataBag $dataBag): Response
    {
        try {

            if (isset($_SESSION['accessToken'])) {
                $this->loginService->endSession($_SESSION['accessToken']);
            }
            $salesChannelId = $context->getSalesChannel()->getId();
            if ($request->hasSession() && $this->loginService->getSysConfig('core.loginRegistration.invalidateSessionOnLogOut', $salesChannelId)) {
                $request->getSession()->invalidate();
            }
            $request->getSession()->remove('state');
            $request->getSession()->remove('access_token');
            $request->getSession()->remove('refresh_token');
            $request->getSession()->remove('sub');
            $parameters = [];
        } catch (ConstraintViolationException $formViolations) {
            $parameters = ['formViolations' => $formViolations];
        }

        return $this->redirectToRoute('frontend.account.login.page', $parameters);
    }

    #[Route(path: '/checkout/register', name: 'frontend.checkout.register.page', options: ['seo' => false], defaults: ['_noStore' => true], methods: ['GET'])]
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

        return $this->renderStorefront("@CidaasOauthConnect/storefront/page/guest.html.twig",
            ['redirectTo' => $redirect, 'errorRoute' => $errorRoute, 'page' => $page, 'data' => $data]
        );
    }

    #[Route(path: '/guest/register', name: 'cidaas.guest.register.page', options: ['seo' => false], defaults: ['_noStore' => true], methods: ['GET'])]
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

    #[Route(path: '/account/register', name: 'frontend.account.register.save', defaults: ['_captcha' => true], methods: ['POST'])]
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

            // this is to show the correct form because we have different use cases (account/register||checkout/register)
            return $this->forwardToRoute($request->get('errorRoute'), ['formViolations' => $formViolations], $params);
        }

        if ($this->loginService->isDoubleOptIn($data, $context)) {
            return $this->redirectToRoute('frontend.account.register.page');
        }

        return $this->createActionResponse($request);
    }

    public function createActionResponse(Request $request): Response
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

}
