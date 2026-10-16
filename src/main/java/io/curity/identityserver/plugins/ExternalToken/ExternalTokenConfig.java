package io.curity.identityserver.plugins.ExternalToken;

import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.annotation.DefaultService;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.HttpClient;
import se.curity.identityserver.sdk.service.issuer.DefaultJwtAccessTokenIssuerProvider;

public interface ExternalTokenConfig extends Configuration
{
    ExceptionFactory getExceptionFactory();

    @DefaultService
    DefaultJwtAccessTokenIssuerProvider getJwtAccessTokenIssuerProvider();

    HttpClient getHttpClient();
}
