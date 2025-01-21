<?php

namespace Cidaas\OauthConnect\Subscriber;

use Shopware\Core\System\SalesChannel\Event\SalesChannelContextSwitchEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Shopware\Core\System\Language\LanguageEntity;


use Shopware\Core\Framework\DataAbstractionLayer\Search\Criteria;
use Shopware\Core\Framework\DataAbstractionLayer\EntityRepositoryInterface;
use Shopware\Core\Framework\DataAbstractionLayer\Search\Filter\EqualsFilter;


class LanguageSwitchSubscriber implements EventSubscriberInterface
{
    private EntityRepositoryInterface $languageRepository;

    public function __construct(EntityRepositoryInterface $languageRepository)
    {
        $this->languageRepository = $languageRepository;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            SalesChannelContextSwitchEvent::class => 'onLanguageSwitch',
        ];
    }


    public function onLanguageSwitch(SalesChannelContextSwitchEvent $event): void
    {
        $context = $event->getSalesChannelContext();
        $newLanguageId = $event->getRequestDataBag()->get('languageId');

        $criteria = new Criteria();
        $criteria->addFilter(new EqualsFilter('id', $newLanguageId));
        $criteria->addAssociation('locale');

        $language = $this->languageRepository->search($criteria, $context->getContext())->first();

        if (!$language || !$language->getLocale()) {
          $_SESSION['locale']= 'en-EN' ;
        }

        $locale = $language->getLocale()->getCode();
        $_SESSION['locale']= $locale;
    }
}
