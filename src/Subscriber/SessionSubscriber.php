<?php



namespace Cidaas\OauthConnect\Subscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Shopware\Storefront\Page\PageLoadedEvent;

class SessionSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents()
    {
        return [
            PageLoadedEvent::class => 'onPageLoaded',
        ];
    }

    public function onPageLoaded(PageLoadedEvent $event)
    {
        // Check if the session is not started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }
}

