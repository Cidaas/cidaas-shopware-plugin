<?php declare(strict_types=1);

namespace Cidaas\OauthConnect\Subscriber;

use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepository;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\Context;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;

class CustomerGroupSubscriber implements EventSubscriberInterface
{
    private $customerGroupTranslationRepo;

    public function __construct(
        EntityRepository $customerGroupTranslationRepo
    ) {
        $this->customerGroupTranslationRepo = $customerGroupTranslationRepo;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            'customer_group.written' => 'onCustomerGroupWritten',
        ];
    }

    public function onCustomerGroupWritten(EntityWrittenEvent $event)
    {
         $writtenEntities = $event->getWriteResults();

         foreach ($writtenEntities as $entity) {
             // Check if the entity is a customer group
             if ($entity->getEntityName() === 'customer_group') {
                 // Get the customer group data
                 $customerGroupData = $entity->getPayload(); 
             }
         }

         $criteria = new Criteria();
         $criteria->addFilter(new EqualsFilter('id', $id));
         $customerGroupName = $this->customerGroupTranslationRepo->search($criteria, Shopware\Context::createDefaultContext())->first();
         error_log($customerGroup->getTranslation('name'));
         
        //  $this->createUrls('aa9b4ad2128946abb182a698b1056ca5', $event->getContext());
    }

    private function createUrls(string $id, Context $context): void
    {
        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('id', $id));
        $customerGroupName = $this->customerGroupTranslationRepo->search($criteria, Shopware\Context::createDefaultContext())->first();
        error_log($customerGroup->getTranslation('name'));
    }
}
