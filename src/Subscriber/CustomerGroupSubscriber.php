<?php declare(strict_types=1);

namespace Cidaas\OauthConnect\Subscriber;

use Shopware\Core\Framework\DataAbstractionLayer\Event\EntityWrittenEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class CustomerGroupSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            'customer_group.written' => 'onCustomerGroupWritten',
        ];
    }

    public function onCustomerGroupWritten(EntityWrittenEvent $event)
    {
        // Check if this event corresponds to a customer group creation or update
        foreach ($event->getWriteResults() as $writeResult) {
            if ($writeResult->getEntityName() === 'customer_group') {
                $customerGroup = $writeResult->getEntity();

                // Your code to create or modify the customer group here
                // Example: $customerGroup->setName('Your New Group Name');
                // /Resources/app/administration/src/module/sw-settings-customer-group
            }
        }
    }
}
