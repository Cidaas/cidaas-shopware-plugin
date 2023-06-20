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
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractLogoutRoute;
use Shopware\Core\Framework\Validation\Exception\ConstraintViolationException;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use GuzzleHttp\Client;

use Cidaas\OauthConnect\Service\CidaasLoginService;
use Shopware\Core\Framework\Uuid\Uuid;


use Cidaas\OauthConnect\Util\CidaasStruct;

/**
 * @RouteScope(scopes={"storefront"})
 */

 class CidaasHelperController extends StorefrontController {

    private $loginService;
    private $cartService;
    private $logoutRoute;

    private $state;

    public function __construct(
        CidaasLoginService $loginService, 
        CartService $cartService,
        AbstractLogoutRoute $logoutRoute
        ) {
        $this->loginService = $loginService;
        $this->cartService = $cartService;
        $this->logoutRoute = $logoutRoute;
    }

    /**
     * @Route("/cidaashelper/dev", methods={"GET"})
     */
    public function dev(Request $req): Response
    {
        $sess = $req->getSession();
        return $this->renderStorefront("@CidaasHelper/storefront/dev/dev.html.twig", []);
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
    }

    /**
     * @Route("/cidaashelper/form", name="cidaashelper.form", methods={"POST"},options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function form(Request $request, SalesChannelContext $context): Response
    {
        // $email = $request->get('email');
        // $response = $this->loginService->login($email, $context);
        // $token = $response->getToken();
        // $this->addCartErrors($this->cartService->getCart($token, $context));
        // return $this->createActionResponse($request);
        return $this->json(array());

        // return $this->json(array(
        //     "dings" => "bums",
        //     "email" => $email,
        //     "text" => $text,
        //     "response" => $response
        // ));
    }

    /**
     * @Route("/cidaas/redirect", name="cidaas.redirect", options={"seo"="false"}, methods={"GET"})
     */
    public function cidaasRedirect(Request $request, SalesChannelContext $context)
    {
        $code = $request->query->get('code');
        $state = $request->query->get('state');
        $sess = $request->getSession()->get('state');
        if ($state === $sess) {
            $token = $this->loginService->getAccessToken($code, $request->get('sw-sales-channel-absolute-base-url'));
            // $request->getSession()->set('ding', $token);
            if (is_array($token)) {
                if (isset($token['sub'])) {
                    $request->getSession()->set('_cidaas_token', $token['access_token']);
                    $request->getSession()->set('sub', $token['sub']);
                    $request->getSession()->set('identity_id', $token['identity_id']);
                    $user = $this->loginService->getAccountFromCidaas($token['access_token']);
                    $temp = $this->loginService->customerExistsByEmail($user['email'], $context);
                    if (!$this->loginService->customerExistsBySub($token['sub'], $context) && !$this->loginService->customerExistsByEmail($user['email'], $context)['exists']) {
                        // $data = $this->loginService->registerExistingUser($user, $context);
                        try {
                            $this->loginService->registerExistingUser($user, $context, $request->get('sw-sales-channel-absolute-base-url'));
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
                    $this->loginService->checkWebshopId($user, $context);
                    $this->loginService->checkCustomerData($user, $context);
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
                    $request->getSession()->set('_cidaas_token', $token->access_token);
                    $request->getSession()->set('sub', $token->sub);
                    $request->getSession()->set('identity_id', $token->identity_id);
                    $user = $this->loginService->getAccountFromCidaas($token->access_token);
                    if (!$this->loginService->customerExistsBySub($token->sub, $context) && !$this->loginService->customerExistsByEmail($user['email'], $context)['exists']) {
                        // $data = $this->loginService->registerExistingUser($user, $context);
                        try {
                            $this->loginService->registerExistingUser($user, $context, $request->get('sw-sales-channel-absolute-base-url'));
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
                    $this->loginService->checkWebshopId($user, $context);
                    $this->loginService->checkCustomerData($user, $context);
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

    /**
     * @Route("/cidaas/logout", name="cidaas.logout", methods={"GET"})
     */
    public function logout(Request $request, SalesChannelContext $context, RequestDataBag $dataBag)
    {
        $token = $request->getSession()->get('_cidaas_token');
        $this->loginService->endSession($token);
        if ($context->getCustomer() === null) {
            return $this->redirectToRoute('frontend.home.page');
        }
        $this->logoutRoute->logout($context, $dataBag);
        $salesChannelId = $context->getSalesChannel()->getId();
        if ($request->hasSession() && $this->loginService->getSysConfig('core.loginRegistration.invalidateSessionOnLogOut', $salesChannelId)) {
            $request->getSession()->invalidate();
        }
        if ($request->query->get('silent')) {
            return $this->redirectToRoute('frontend.home.page');
        }
        if ($request->query->get('session')) {
            $this->addFlash('warning', 'Deine Sitzung ist abgelaufen, bitte melde dich erneut an.');
        }
        $this->addFlash('success', $this->trans('account.logoutSucceeded'));
        $request->getSession()->remove('state');
        $request->getSession()->remove('_cidaas_token');
        $request->getSession()->remove('sub');
        return $this->redirectToRoute('frontend.home.page');
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
        $red = $this->loginService->getAuthorizationUri($state, $request->get('sw-sales-channel-absolute-base-url'));
        return new RedirectResponse($red);
    }

    /**
     * @Route("/cidaas/register", name="cidaas.register", methods={"GET"}, options={"seo"="false"})
     */
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

    /**
     * @Route("/cidaas/identity/login", name="cidaas.identity.login")
     */
    public function identityLogin(Request $request, SalesChannelContext $context): Response
    {
        if ($request->query->get('error')) {
            if ($request->query->get('error') === 'invalid_username_password') {
                $this->addFlash('danger', 'Falsche E-Mail oder Passwort');
            } else {
                $this->addFlash('danger', 'Fehler bei der Anmeldung');
            }
        }
        $requestId = $request->query->get('requestId');
        $cidaasUrl = $this->loginService->getCidaasUrl();
        return $this->renderStorefront("@CidaasHelper/storefront/dev/dev.html.twig", [
            'requestId' => $requestId,
            'cidaas' => $cidaasUrl
        ]);
    }

    /**
     * @Route("/cidaas/changepassword", name="cidaas.changepassword", methods={"GET", "POST"}, options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function changepassword(Request $request, SalesChannelContext $context): Response
    {
        //authz-srv/authz/?response_type=token&client_id=96d26174-49bb-4278-84db-e109c55144e4&viewtype=login&redirect_uri=https://my-test.mainz05.de/user-profile/changepassword
        $sub = $request->getSession()->get('sub');
        $identityId = $request->getSession()->get('identity_id');
        $token = $request->getSession()->get('_cidaas_token');
        $newPassword = $request->get('newPassword');
        $confirmPassword = $request->get('confirmPassword');
        $oldPassword = $request->get('oldPassword');
        $res = $this->loginService->changepassword($newPassword, $confirmPassword, $oldPassword, $identityId, $token);
        $this->addFlash('success', 'Passwort erfolgreich geändert');
        return $this->json($res);
        
        // $result = $request->query->get('result');
        // if ($request->getMethod() === 'POST')
        //     $result = $request->get('result');
        // if ($result) {
        //     $this->addFlash('success', 'Passwort erfolgreich geändert');
        // } 
        // return $this->json(array(
        //     'success' => $result
        // ));
    }

    /**
     * @Route("/cidaas/emailform", name="cidaas.emailform", methods={"POST"}, options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function emailForm(Request $request, SalesChannelContext $context): Response
    {
        $sub = $request->getSession()->get('sub');
        $email = $request->get('email');
        $this->loginService->changeEmail($email, $sub, $context);
        $this->addFlash('success', 'E-Mail Adresse geändert');
        return $this->json(
            array(
            )
        );
    }

     /**
     * @Route("/cidaas/update-profile", name="frontend.account.profile.save", methods={"POST"}, options={"seo"="false"}, defaults={"XmlHttpRequest"=true})
     */
    public function updateProfile(Request $request, SalesChannelContext $context): Response
    {
        $sub = $request->getSession()->get('sub');
        $identityId = $request->getSession()->get('identity_id');
        $firstName = $request->get('firstName');
        $lastName = $request->get('lastName');
        $salutationId = $request->get('salutationId');
        $res = $this->loginService->updateProfile($firstName, $lastName, $salutationId, $sub, $context);
        if($res->success) {
            $this->addFlash('success', 'Successfully updated profile');
        } else {
            error_log(json_encode($res));
            $this->addFlash('danger', 'Failed to update profile');
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
 }
