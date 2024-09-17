<?php

namespace SocialiteProviders\OIDC;

use SocialiteProviders\Manager\SocialiteWasCalled;

class OIDCExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('oidc', Provider::class);
    }
}
