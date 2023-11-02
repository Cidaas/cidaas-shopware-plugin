<?php declare( strict_types = 1 );

namespace Cidaas\OauthConnect\Subscriber;

use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;
use Cidaas\OauthConnect\Service\CidaasLoginService;

class CustomerGroupSubscriber implements EventSubscriberInterface {
    private $loginService;

    public function __construct(
        private readonly EntityRepository $customerGroupRepository,
        CidaasLoginService $loginService
    ) {
        $this->loginService = $loginService;
    }

    public static function getSubscribedEvents(): array {
        return [
            'customer_group.written' => 'onCustomerGroupWritten',
        ];
    }

    public function onCustomerGroupWritten( EntityWrittenEvent $event ) {
        // Your code to handle the event here
        foreach ( $event->getWriteResults() as $writeResult ) {
            // Check if the event is related to a customer group
            if ( $writeResult->getEntityName() === 'customer_group' ) {
                // Get the customer group ID from the event
                $customerGroupId = $writeResult->getPrimaryKey();

                // Fetch the customer group data from the repository
                $criteria = new Criteria();
                $criteria->addFilter( new EqualsFilter( 'id', $customerGroupId ) );
                $customerGroup = $this->customerGroupRepository->search( $criteria, $event->getContext() )->first();

                // get the customer group name
                $customerGroupName = $customerGroup->getTranslation( 'name' );
                $res =  $this->loginService->createCustomerGroup( $customerGroupId, $customerGroupName );
                error_log( json_encode( $res ) );
            }
        }
    }
}
