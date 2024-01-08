<?php declare( strict_types = 1 );

namespace Cidaas\OauthConnect\Controller;

use Shopware\Storefront\Controller\StorefrontController;
use Symfony\Component\Routing\Annotation\Route;
use Shopware\Core\Framework\Routing\Annotation\RouteScope;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Shopware\Core\System\SalesChannel\SalesChannelContext;
use Shopware\Core\Checkout\Customer\SalesChannel\AccountService;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractListAddressRoute;
use Shopware\Core\Framework\Validation\Exception\ConstraintViolationException;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Shopware\Core\Checkout\Customer\Exception\AddressNotFoundException;
use Shopware\Core\Framework\Validation\DataBag\RequestDataBag;
use GuzzleHttp\Client;
use Cidaas\OauthConnect\Service\CidaasLoginService;
use Shopware\Core\Framework\Uuid\Uuid;
use Shopware\Core\Framework\Validation\DataBag\DataBag;
use Shopware\Core\Checkout\Customer\CustomerEntity;
use Shopware\Core\Checkout\Customer\CustomerException;
use Shopware\Core\Checkout\Customer\Aggregate\CustomerAddress\CustomerAddressEntity;
use Shopware\Core\Framework\Uuid\Exception\InvalidUuidException;
use Cidaas\OauthConnect\Util\CidaasStruct;
use Shopware\Core\Framework\Routing\RoutingException;
use Shopware\Storefront\Page\Address\AddressEditorModalStruct;
use Shopware\Storefront\Page\Address\Listing\AddressBookWidgetLoadedHook;
use Shopware\Storefront\Page\Address\Listing\AddressListingPageLoader;
use Shopware\Core\Checkout\Cart\Exception\CustomerNotLoggedInException;
use Shopware\Core\Checkout\Cart\Order\Transformer\CustomerTransformer;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractUpsertAddressRoute;
use Shopware\Core\Checkout\Customer\SalesChannel\AbstractChangeCustomerProfileRoute;

#[ Route( defaults: [ '_routeScope' => [ 'storefront' ] ] ) ]

class CidaasAddressController extends StorefrontController {

    private const ADDRESS_TYPE_BILLING = 'billing';
    private const ADDRESS_TYPE_SHIPPING = 'shipping';
    private $state;

    public function __construct(
        private readonly CidaasLoginService $loginService,
        private readonly AbstractListAddressRoute $listAddressRoute,
        private readonly AccountService $accountService,
        private readonly AddressListingPageLoader $addressListingPageLoader,
        private readonly AbstractUpsertAddressRoute $updateAddressRoute,
        private readonly AbstractChangeCustomerProfileRoute $updateCustomerProfileRoute
    ) {
    }

    // Update billing address to Cidaas
    #[ Route( path: '/cidaas/update-address', name: 'frontend.account.address.edit.save', options: [ 'seo' => false ], defaults: [ '_loginRequired' => true ], methods: [ 'POST' ] ) ]

    public function billingAddressUpdate( Request $request, RequestDataBag $data, SalesChannelContext $context,  CustomerEntity $customer ): Response {

        $addressData = $this->convertToCustomerAddressEntity( $data );
        $sub = $request->getSession()->get( 'sub' );
        $activeBillingAddress = $customer->getActiveBillingAddress();
        $activeBillingAddressId = $activeBillingAddress->get( 'id' );
        $addressId =  $addressData->get( 'id' );

        if ( $addressId === $activeBillingAddressId ) {
            $this->updateBillingAddressToCidaas( $addressData, $sub, $context );
        } else {
            $this->loginService->updateAddressToShopware( $addressData, $context );
        }
        return $this->redirectToRoute( 'frontend.account.address.page' );
    }

    // Select the address and update based on the selection of billing and shipping addresses
    #[ Route( path: '/cidaas/address/default-{type}/{addressId}', name: 'frontend.account.address.set-default-address', defaults: [ '_loginRequired' => true ], methods: [ 'POST' ] ) ]

    public function switchDefaultAddresses( Request $request, string $type, string $addressId, SalesChannelContext $context, CustomerEntity $customer ): RedirectResponse {
        if ( !Uuid::isValid( $addressId ) ) {
            throw new InvalidUuidException( $addressId );
        }
        try {
            if ( $type === self::ADDRESS_TYPE_SHIPPING ) {
                $this->accountService->setDefaultShippingAddress( $addressId, $context, $customer );
            } elseif ( $type === self::ADDRESS_TYPE_BILLING ) {
                $sub = $request->getSession()->get( 'sub' );
                $address = $this->getById( $addressId, $context, $customer );
                $this->updateBillingAddressToCidaas( $address, $sub, $context );
                $this->accountService->setDefaultBillingAddress( $addressId, $context, $customer );
            } else {
                $this->addFlash( 'danger', 'Address not found' );
            }
        } catch ( AddressNotFoundException ) {
            $this->addFlash( 'danger', 'Address not found' );
        }
        return $this->redirectToRoute( 'frontend.account.address.page' );
    }

    private function updateBillingAddressToCidaas( CustomerAddressEntity $address, string $sub, SalesChannelContext $context ) {
        $res = $this->loginService->updateBillingAddress( $address, $sub, $context );
        if ( $res ) {
            // Assuming $object is your stdClass object
            $responseData = json_decode( json_encode( $res ), true );
            // Key exists in the array
            if ( array_key_exists( 'success', $responseData ) ) {
                if ( $responseData[ 'success' ] === true ) {
                    $this->addFlash( 'success', 'Successfully updated Billing address' );
                } elseif ( $responseData[ 'success' ] === false ) {
                    if ( array_key_exists( 'error', $responseData ) ) {
                        // Handle error data
                        // Extract error details
                        $error = $responseData[ 'error' ][ 'error' ];
                        $this->addFlash( 'danger', 'Failed to update billing address: '.$error );
                    } else {
                        // No error information available
                        error_log( json_encode( $responseData ) );
                        $this->addFlash( 'danger', 'Failed to update billing address for unknown reason. Please check error log for more details.' );
                    }
                } else {
                    $this->addFlash( 'danger', 'Failed to update billing address for unknown reason.' );
                }
            } else {
                // Key does not exist in the array
                $this->addFlash( 'danger', 'Failed to update billing address for unknown reason.' );
            }
        } else {
            $this->addFlash( 'danger', 'Failed to update billing address for unknown reason.' );
        }
    }

    // Get customer ID based on address ID
    private function getById( string $addressId, SalesChannelContext $context, CustomerEntity $customer ): CustomerAddressEntity {
        if ( !Uuid::isValid( $addressId ) ) {
            throw new InvalidUuidException( $addressId );
        }
        $criteria = new Criteria();
        $criteria->addFilter( new EqualsFilter( 'id', $addressId ) );
        $criteria->addFilter( new EqualsFilter( 'customerId', $customer->getId() ) );
        $address = $this->listAddressRoute->load( $criteria, $context, $customer )->getAddressCollection()->get( $addressId );
        if ( !$address ) {
            throw CustomerException::addressNotFound( $addressId );
        }
        return $address;
    }

    public function convertToCustomerAddressEntity( RequestDataBag $data ): CustomerAddressEntity {
        /** @var RequestDataBag $address */

        $address = $data->get( 'address' );
        $addressArray = [
            'id' => $address->get( 'id' ),
            'salutationId' => $address->get( 'salutationId' ),
            'firstName' => $address->get( 'firstName' ),
            'lastName' => $address->get( 'lastName' ),
            'street' => $address->get( 'street' ),
            'city' => $address->get( 'city' ),
            'zipcode' => $address->get( 'zipcode' ),
            'countryId' => $address->get( 'countryId' ),
            'countryStateId' => $address->get( 'countryStateId' ),
            'company' => $address->get( 'company' ),
            'department' => $address->get( 'department' )
        ];

        // Create a new CustomerAddressEntity instance
        $addressEntity = new CustomerAddressEntity();
        $addressEntity->assign( $addressArray );

        return $addressEntity;
    }

    // update address-book through pop up while checkout the cart
    #[ Route( path: '/widgets/account/address-book', name: 'frontend.account.addressbook', options: [ 'seo' => true ], defaults: [ 'XmlHttpRequest' => true, '_loginRequired' => true, '_loginRequiredAllowGuest' => true ], methods: [ 'POST' ] ) ]

    public function addressBook( Request $request, RequestDataBag $dataBag, SalesChannelContext $context, CustomerEntity $customer ): Response {
        $viewData = new AddressEditorModalStruct();
        $params = [];

        try {
            $page = $this->addressListingPageLoader->load( $request, $context, $customer );
            $this->hook( new AddressBookWidgetLoadedHook( $page, $context ) );
            $viewData->setPage( $page );

            $this->handleChangeableAddresses( $viewData, $dataBag, $context, $customer );
            $this->handleAddressCreation( $viewData, $dataBag, $context, $customer );
            $this->handleAddressSelection( $viewData, $dataBag, $context, $customer );
            $this->handleCustomerVatIds( $dataBag, $context, $customer );
        } catch ( ConstraintViolationException $formViolations ) {
            $params[ 'formViolations' ] = $formViolations;
            $params[ 'postedData' ] = $dataBag->get( 'address' );
        } catch ( \Exception ) {
            $viewData->setSuccess( false );
            $viewData->setMessages( [
                'type' => self::DANGER,
                'text' => $this->trans( 'error.message-default' ),
            ] );
        }

        if ( $request->get( 'redirectTo' ) || $request->get( 'forwardTo' ) ) {
            return $this->createActionResponse( $request );
        }
        $params = array_merge( $params, $viewData->getVars() );

        $response = $this->renderStorefront(
            '@Storefront/storefront/component/address/address-editor-modal.html.twig',
            $params
        );

        $response->headers->set( 'x-robots-tag', 'noindex' );

        return $response;
    }

    private function handleAddressCreation(
        AddressEditorModalStruct $viewData,
        RequestDataBag $dataBag,
        SalesChannelContext $context,
        CustomerEntity $customer
    ): void {
        /** @var DataBag|null $addressData */
        $addressData = $dataBag->get( 'address' );
        if ( $addressData === null ) {
            return;
        }
        $response = $this->updateAddressRoute->upsert(
            $addressData->get( 'id' ),
            $addressData->toRequestDataBag(),
            $context,
            $customer
        );
        $addressId = $response->getAddress()->getId();
        $addressType = null;
        if ( $viewData->isChangeBilling() ) {
            $addressType = self::ADDRESS_TYPE_BILLING;
        } elseif ( $viewData->isChangeShipping() ) {
            $addressType = self::ADDRESS_TYPE_SHIPPING;
        }
        // prepare data to set newly created address as customers default
        if ( $addressType ) {
            $dataBag->set( 'selectAddress', new RequestDataBag( [
                'id' => $addressId,
                'type' => $addressType,
            ] ) );
        }
        $viewData->setAddressId( $addressId );
        $viewData->setSuccess( true );
        $viewData->setMessages( [ 'type' => 'success', 'text' => $this->trans( 'account.addressSaved' ) ] );
    }

    private function handleChangeableAddresses(
        AddressEditorModalStruct $viewData,
        RequestDataBag $dataBag,
        SalesChannelContext $context,
        CustomerEntity $customer
    ): void {
        $changeableAddresses = $dataBag->get( 'changeableAddresses' );
        if ( !$changeableAddresses instanceof DataBag ) {
            return;
        }
        $viewData->setChangeShipping( ( bool ) $changeableAddresses->get( 'changeShipping' ) );
        $viewData->setChangeBilling( ( bool ) $changeableAddresses->get( 'changeBilling' ) );

        $addressId = $dataBag->get( 'id' );

        if ( !$addressId ) {
            return;
        }
        $viewData->setAddress( $this->getById( $addressId, $context, $customer ) );
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
        $selectedAddress = $dataBag->get( 'selectAddress' );
        if ( !$selectedAddress instanceof DataBag ) {
            return;
        }
        $addressType = $selectedAddress->get( 'type' );
        $addressId = $selectedAddress->get( 'id' );
        if ( !Uuid::isValid( $addressId ) ) {
            throw new InvalidUuidException( $addressId );
        }
        $success = true;
        try {
            if ( $addressType === self::ADDRESS_TYPE_SHIPPING ) {
                $address = $this->getById( $addressId, $context, $customer );
                $customer->setDefaultShippingAddress( $address );
                $this->accountService->setDefaultShippingAddress( $addressId, $context, $customer );
            } elseif ( $addressType === self::ADDRESS_TYPE_BILLING ) {
                $address = $this->getById( $addressId, $context, $customer );
                $customer->setDefaultBillingAddress( $address );
                $this->accountService->setDefaultBillingAddress( $addressId, $context, $customer );
                $sub = $this->loginService->getSubFromCustomFields( $customer );
                if ( $sub ) {
                    $this->updateBillingAddressToCidaas( $address, $sub, $context );
                }
            } else {
                $success = false;
            }
        } catch ( AddressNotFoundException ) {
            $success = false;
        }

        if ( $success ) {
            $this->addFlash( self::SUCCESS, $this->trans( 'account.addressDefaultChanged' ) );
        } else {
            $this->addFlash( self::DANGER, $this->trans( 'account.addressDefaultNotChanged' ) );
        }

        $viewData->setSuccess( $success );
    }

    private function handleCustomerVatIds( RequestDataBag $dataBag, SalesChannelContext $context, CustomerEntity $customer ): void {
        $dataBagVatIds = $dataBag->get( 'vatIds' );
        if ( !$dataBagVatIds instanceof DataBag ) {
            return;
        }
        $newVatIds = $dataBagVatIds->all();
        $oldVatIds = $customer->getVatIds() ?? [];
        if ( !array_diff( $newVatIds, $oldVatIds ) && !array_diff( $oldVatIds, $newVatIds ) ) {
            return;
        }
        $dataCustomer = CustomerTransformer::transform( $customer );
        $dataCustomer[ 'vatIds' ] = $newVatIds;
        $dataCustomer[ 'accountType' ] = $customer->getCompany() === null ? CustomerEntity::ACCOUNT_TYPE_PRIVATE : CustomerEntity::ACCOUNT_TYPE_BUSINESS;

        $newDataBag = new RequestDataBag( $dataCustomer );

        $this->updateCustomerProfileRoute->change( $newDataBag, $context, $customer );
    }

}
