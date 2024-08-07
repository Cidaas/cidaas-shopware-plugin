<?php declare (strict_types = 1);

namespace Cidaas\OauthConnect\Controller;

use Cidaas\OauthConnect\Service\CidaasLoginService;
use Shopware\Core\Checkout\Cart\SalesChannel\CartService;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractChangeCustomerProfileRoute;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractLogoutRoute;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use Shopware\Core\Framework\Validation\Exception\ConstraintViolationException;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Storefront\Controller\StorefrontController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route(defaults: ['_routeScope' => ['storefront']])]

class CidaasHelperController extends StorefrontController
{

    public function __construct(
        private readonly CidaasLoginService $loginService,
        private readonly CartService $cartService,
        private readonly AbstractLogoutRoute $logoutRoute,
        private readonly AbstractChangeCustomerProfileRoute $updateCustomerProfileRoute
    ) {
    }

    // Redirect all account login
    #[Route(path: '/account/login', name: 'frontend.account.login.page')]
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

    // handle redirect from Cidaas
    #[Route(path: '/cidaas/redirect', name: 'cidaas.redirect', options: ['seo' => false], methods: ['GET'])]
    public function cidaasRedirect(Request $request, SalesChannelContext $context)
    {
        $code = $request->query->get('code');
        $state = $request->query->get('state');
        $sessionState = $request->getSession()->get('state');

        if ($state !== $sessionState) {
            $this->addFlash(self::DANGER, $this->trans('account.loginError'));
            return $this->forwardToRoute('frontend.home.page');
        }

        $baseUrl = $request->get('sw-sales-channel-absolute-base-url');
        $token = $this->loginService->getCidaasAccessToken($code, $baseUrl);

        if (!$token || (!is_array($token) && !is_object($token))) {
            $this->addFlash(self::DANGER, $this->trans('account.loginError'));
            return $this->forwardToRoute('frontend.home.page');
        }

        $accessToken = is_array($token) ? $token['access_token'] : $token->access_token;
        $sub = is_array($token) ? $token['sub'] : $token->sub;
        $refreshToken = is_array($token) ? $token['refresh_token'] : $token->refresh_token ?? null;

        $_SESSION['accessToken'] = $accessToken;
        if ($refreshToken) {
            $_SESSION['refreshToken'] = $refreshToken;
        }
        $request->getSession()->set('sub', $sub);

        $user = $this->loginService->getAccountFromCidaas($accessToken);
        $email = $user['email'];
        $customerExistsBySub = $this->loginService->customerExistsBySub($sub, $context);
        $customerExistsByEmail = $this->loginService->customerExistsByEmail($email, $context)['exists'];

        if (!$customerExistsBySub && !$customerExistsByEmail) {
            try {
                $this->loginService->registerExistingUser($user, $context, $baseUrl);
                $this->loginService->checkCustomerGroups($user, $context);
                return $this->handleRedirect($request);
            } catch (ConstraintViolationException $formViolations) {
                $error = $formViolations->getMessage();
                $this->addFlash('danger', 'Error: ' . $error);
                return $this->forwardToRoute('frontend.home.page', [
                    'loginError' => true,
                    'errorSnippet' => $error,
                ]);
            }
        }

        if (!$customerExistsBySub && $customerExistsByEmail) {
            $this->loginService->mapSubToCustomer($email, $sub, $context);
        }

        $this->loginService->checkCustomerGroups($user, $context);
        $this->loginService->checkCustomerNumber($user, $context);
        $this->loginService->checkWebshopId($user, $accessToken, $context);
        $this->loginService->updateAddressData($user, $context);
        $this->loginService->updateCustomerFromCidaas($user, $context);

        $response = $this->loginService->loginBySub($sub, $context);
        $request->getSession()->set('sub', $sub);
        $this->addCartErrors($this->cartService->getCart($response->getToken(), $context));

        return $this->handleRedirect($request);
    }

/**
 * Handles redirect logic after a successful login.
 *
 * @param Request $request
 * @return Response
 */
    private function handleRedirect(Request $request)
    {
        if ($request->getSession()->get('redirect_to')) {
            $target = $request->getSession()->get('redirect_to');
            $request->getSession()->remove('redirect_to');

            if ($redirectParameters = $request->getSession()->get('redirectParameters')) {
                $request->getSession()->remove('redirectParameters');
                return $this->forwardToRoute($target, [], json_decode(json_encode($redirectParameters), true));
            }

            return $this->forwardToRoute($target);
        }

        $this->addFlash(self::SUCCESS, $this->trans('account.loginSuccess'));
        return $this->forwardToRoute('frontend.home.page');
    }

    public function hasRequiredUserData($user)
    {
        // Define the required fields and nested fields
        $requiredFields = [
            'given_name',
            'family_name',
            'email',
            'customFields.billing_address_street',
            'customFields.billing_address_zipcode',
            'customFields.billing_address_city',
        ];

        // Check if all required fields are present
        foreach ($requiredFields as $field) {
            if (!$this->isFieldSet($user, $field)) {
                return false; // At least one required field is missing
            }
        }
        return true; // All required data is present
    }

    // Helper function to check if a nested field is set
    private function isFieldSet($array, $field)
    {
        $keys = explode('.', $field);
        foreach ($keys as $key) {
            if (!isset($array[$key])) {
                return false;
            }
            $array = $array[$key];
        }
        return true;
    }

    #[Route(path: '/account/logout', name: 'frontend.account.logout.page', methods: ['GET'])]
    public function logout(Request $request, SalesChannelContext $context, RequestDataBag $dataBag): Response
    {
        // Redirect to login page if the customer is not logged in
        if ($context->getCustomer() === null) {
            return $this->redirectToRoute('frontend.account.login.page');
        }

        try {
            // End the session if an access token is present
            if (isset($_SESSION['accessToken'])) {
                $this->loginService->endSession($_SESSION['accessToken']);
            }

            // Perform the logout operation
            $this->logoutRoute->logout($context, $dataBag);

            // Add a success message for the logout
            $this->addFlash(self::SUCCESS, $this->trans('account.logoutSucceeded'));

            // Get the current sales channel ID
            $salesChannelId = $context->getSalesChannel()->getId();

            // Check if the request has a session and invalidate it if needed
            $session = $request->getSession();
            if ($request->hasSession() && $this->loginService->getSysConfig('core.loginRegistration.invalidateSessionOnLogOut', $salesChannelId)) {
                $session->invalidate();
            } else {
                // Remove specific session attributes if the session is not invalidated
                $session->remove('state');
                $session->remove('sub');
            }

            // Clear all session variables
            session_unset();

            // Prepare parameters for the redirect
            $parameters = [];
        } catch (ConstraintViolationException $formViolations) {
            // Handle form validation errors
            $parameters = ['formViolations' => $formViolations];
        }

        // Redirect to the login page with any parameters
        return $this->redirectToRoute('frontend.account.login.page', $parameters);
    }

    #[Route(path: '/cidaas/exists', name: 'cidaas.exists', options: ['seo' => false], defaults: ['XmlHttpRequest' => true], methods: ['POST'])]
    public function exists(Request $request, SalesChannelContext $context): Response
    {
        $email = $request->get('email');
        $exists = $this->loginService->customerExistsByEmail($email, $context);
        return $this->json($exists);
    }

    #[Route(path: '/cidaas/authuri/{email}', name: 'cidaas.authuri', options: ['seo' => false], defaults: ['XmlHttpRequest' => true], methods: ['GET'])]
    public function authuri(Request $request, $email): Response
    {
        if ($request->getSession()->get('state')) {
            $state = $request->getSession()->get('state');
        }
        $authUri = $this->loginService->getAuthorizationUri($state, $request->get('sw-sales-channel-absolute-base-url', $email));
        return $this->json(array(
            'authUri' => $authUri,
        ));
    }

    #[Route(path: '/cidaas/lastlogin/{customerId}', name: 'cidaas.lastlogin', options: ['seo' => false], defaults: ['XmlHttpRequest' => true], methods: ['GET'])]
    public function lastLogin(Request $request, SalesChannelContext $context, $customerId): Response
    {
        $lastLogin = $this->loginService->getLastLogin($customerId, $context);
        return $this->json(array(
            'lastLogin' => $lastLogin,
        ));
    }

    #[Route(path: '/cidaas/login', name: 'cidaas.login', options: ['seo' => false], defaults: ['XmlHttpRequest' => true], methods: ['GET'])]
    public function cidaasLogin(Request $request, SalesChannelContext $context): Response
    {
        if ($request->query->get('redirect_to')) {
            $request->getSession()->set('redirect_to', $request->query->get('redirect_to'));
        }
        if ($request->get('redirectTo')) {
            $request->getSession()->set('redirect_to', $request->get('redirectTo'));
        }
        if ($request->get('redirectParameters')) {
            $request->getSession()->set('redirectParameters', $request->get('redirectParameters'));
        }
        $state = Uuid::randomHex();
        if ($request->getSession()->get('state')) {
            $state = $request->getSession()->get('state');
        } else {
            $request->getSession()->set('state', $state);
        }
        $red = $this->loginService->getAuthorizationUri($state, $request->get('sw-sales-channel-absolute-base-url'));
        return new RedirectResponse($red);
    }

    #[Route(path: '/cidaas/changepassword', name: 'cidaas.changepassword', options: ['seo' => false], defaults: ['XmlHttpRequest' => true], methods: ['GET', 'POST'])]
    public function changepassword(Request $request, SalesChannelContext $context): Response
    {
        try {
            $sub = $request->getSession()->get('sub');

            $newPassword = $request->get('newPassword');
            $confirmPassword = $request->get('confirmPassword');
            $oldPassword = $request->get('oldPassword');

            // Attempt to change the password
            $res = $this->loginService->changepassword($newPassword, $confirmPassword, $oldPassword, $sub);

            $responseData = json_decode(json_encode($res), true);

            if (!$res || !array_key_exists('success', $responseData)) {
                throw new \Exception($this->trans('account.passwordChangeSuccess'));
            }
            if ($responseData['success'] === true) {
                $this->addFlash(self::SUCCESS, $this->trans('account.passwordChangeSuccess'));
            } else {
                $error = $responseData['error']['error'] ?? 'Unknown error';
                $this->addFlash(self::DANGER, $this->trans('account.passwordChangeNoSuccess') . $error);
            }
            return $this->json($res);
        } catch (\Exception $e) {
            $this->addFlash(self::DANGER, $this->trans('account.passwordChangeNoSuccess') . $e->getMessage());
            return $this->json(['success' => false, 'message' => $e->getMessage()], Response::HTTP_BAD_REQUEST);
        }
    }

    #[Route(path: '/cidaas/emailform', name: 'cidaas.emailform', options: ['seo' => false], defaults: ['XmlHttpRequest' => true], methods: ['POST'])]
    public function emailForm(Request $request, SalesChannelContext $context): Response
    {
        try {
            $sub = $request->getSession()->get('sub');
            $email = $request->get('email');

            $res = $this->loginService->changeEmail($email, $sub, $context);

            $responseData = json_decode(json_encode($res), true);

            if (!$res || !array_key_exists('success', $responseData)) {
                throw new \Exception($this->trans('account.emailChangeNoSuccess'));
            }
            if ($responseData['success'] === true) {
                $this->addFlash(self::SUCCESS, $this->trans('account.emailChangeSuccess'));
            } else {
                $error = $responseData['error']['error'] ?? 'Unknown error';
                $this->addFlash(self::DANGER, $this->trans('account.emailChangeNoSuccess') . $error);
            }

            return $this->json($res);
        } catch (\Exception $e) {
            $this->addFlash(self::DANGER, $this->trans('account.emailChangeNoSuccess') . $e->getMessage());
            return $this->json(['success' => false, 'message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[Route(path: '/cidaas/update-profile', name: 'frontend.account.profile.save', defaults: ['_loginRequired' => true], methods: ['POST'])]
    public function updateProfile(Request $request, RequestDataBag $data, SalesChannelContext $context, CustomerEntity $customer): Response
    {
        $session = $request->getSession();
        $sub = $session->get('sub');
        $firstName = $request->get('firstName');
        $lastName = $request->get('lastName');
        $salutationId = $request->get('salutationId');

        try {
            // Update profile
            $res = $this->loginService->updateProfile($firstName, $lastName, $salutationId, $sub, $context);
            $responseData = json_decode(json_encode($res), true);

            if (!$res || !array_key_exists('success', $responseData)) {
                throw new \Exception($this->trans('account.updateProfileError'));
            }

            if ($responseData['success'] === true) {
                $this->updateCustomerProfileRoute->change($data, $context, $customer);
                $this->addFlash(self::SUCCESS, $this->trans('account.updateProfile'));
            } else {
                $error = $responseData['error']['error'] ?? 'Unknown error';
                $this->addFlash(self::DANGER, $this->trans('account.updateProfileError') . $error);
            }
        } catch (\Exception $e) {
            error_log($e->getMessage());
            $this->addFlash(self::DANGER, $this->trans('account.updateProfileError') . $e->getMessage());
        }

        return $this->redirectToRoute('frontend.account.profile.page');
    }

    #[Route(path: '/cidaas/url', name: 'cidaas.url', options: ['seo' => false], defaults: ['XmlHttpRequest' => true], methods: ['GET'])]
    public function getUrl(Request $request): Response
    {
        return $this->json(array(
            'url' => $this->loginService->getCidaasUrl(),
        ));
    }

    #[Route(path: '/cidaas/generate', name: 'cidaas.generate', options: ['seo' => false], defaults: ['XmlHttpRequest' => true], methods: ['POST'])]
    public function generateRequest(Request $request): Response
    {
        $clientId = $this->loginService->getSysConfig('CidaasHelper.config.clientId');
        $url = $request->get('sw-sales-channel-absolute-base-url') . '/cidaas/redirect';
        $state = $request->getSession()->get('state');
        return $this->json(
            array(
                'clientId' => $clientId,
                'url' => $url,
                'state' => $state,
            )
        );
    }
}
