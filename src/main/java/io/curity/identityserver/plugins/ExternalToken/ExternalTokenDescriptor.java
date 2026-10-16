package io.curity.identityserver.plugins.ExternalToken;

import java.util.Optional;

import se.curity.identityserver.sdk.plugin.ManagedObject;
import se.curity.identityserver.sdk.plugin.descriptor.TokenProcedurePluginDescriptor;
import se.curity.identityserver.sdk.procedure.token.OAuthTokenExchangeTokenProcedure;

public final class ExternalTokenDescriptor implements TokenProcedurePluginDescriptor<ExternalTokenConfig> {
    @Override
    public Class<? extends OAuthTokenExchangeTokenProcedure> getOAuthTokenEndpointOAuthTokenExchangeTokenProcedure() {
        return ExternalTokenProcedure.class;
    }

    @Override
    public String getPluginImplementationType() {
        return "entra-external-token";
    }

    @Override
    public Class<? extends ExternalTokenConfig> getConfigurationType() {
        return ExternalTokenConfig.class;
    }

    @Override
    public Optional<JwtValidator> createManagedObject(ExternalTokenConfig configuration) {
        return Optional.of(new JwtValidator(configuration));
    }
}
