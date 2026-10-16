package io.curity.identityserver.plugins.ExternalToken;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.SubjectAttributes;
import se.curity.identityserver.sdk.attribute.token.AccessTokenAttributes;
import se.curity.identityserver.sdk.data.authorization.Delegation;
import se.curity.identityserver.sdk.data.tokens.TokenIssuerException;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.procedure.token.OAuthTokenExchangeTokenProcedure;
import se.curity.identityserver.sdk.procedure.token.context.OAuthTokenExchangeUnInitializedTokenProcedurePluginContext;
import se.curity.identityserver.sdk.procedure.token.context.PresentedToken;
import se.curity.identityserver.sdk.service.issuer.AccessTokenIssuer;
import se.curity.identityserver.sdk.service.issuer.DefaultJwtAccessTokenIssuerProvider;
import se.curity.identityserver.sdk.web.ResponseModel;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class ExternalTokenProcedure implements OAuthTokenExchangeTokenProcedure {
    private static final Logger _logger = LoggerFactory.getLogger(ExternalTokenProcedure.class);
    private final ExternalTokenConfig _configuration;
    private final JwtValidator _validator;

    public ExternalTokenProcedure(ExternalTokenConfig configuration, JwtValidator validatior) {
        _configuration = configuration;
        _validator = validatior;
    }

    @Override
    public ResponseModel run(OAuthTokenExchangeUnInitializedTokenProcedurePluginContext context) {
        var externalToken = context.getSubjectTokenValue();
        var subjectTokenClaims = validateJwt(externalToken);
        var subject = subjectTokenClaims.getSubject();

        var subjectAttributes = SubjectAttributes.of(subject);
        var intendedAudience = new HashSet<String>();
        var intendedScopes = new HashSet<String>();
        context.getInitializedContext(subjectAttributes, null, intendedAudience, intendedScopes);

        var delegationData = context.getDefaultDelegationData();
        var issuedDelegation = context.getDelegationIssuer().issue(delegationData);

        var accessTokenData = context.getDefaultAccessTokenData();
        accessTokenData = accessTokenData.withActor(context.getClient().getId());
        var issuedAccessToken = "";
        try {
            issuedAccessToken = context.getAccessTokenIssuer().issue(accessTokenData, issuedDelegation);
        } catch (TokenIssuerException e) {
            _logger.warn(e.getMessage());
        }
        // context.accessTokenIssuer.issue(accessTokenData, issuedDelegation);

        String token = context.getSubjectTokenValue();
        var b = validateJwt(token);
        DefaultJwtAccessTokenIssuerProvider provider = _configuration.getJwtAccessTokenIssuerProvider();

        try {
            @Nullable
            AccessTokenIssuer issuer = provider.getDefaultJwtAccessTokenIssuer();
            if (issuer == null) {
                throw _configuration.getExceptionFactory().badRequestException(ErrorCode.TOKEN_ISSUANCE_ERROR,
                        "JSON Web Tokens not enabled.");
            }
            if (issuedAccessToken == null) {
                throw _configuration.getExceptionFactory().badRequestException(ErrorCode.TOKEN_ISSUANCE_ERROR,
                        "No access token issued.");
            }

            HashMap<String, Object> responseData = new HashMap<>();
            // responseData.put("scope", tokenAttributes.getScope());
            responseData.put("access_token", issuedAccessToken);
            responseData.put("token_type", "bearer");
            // responseData.put("expires_in", tokenAttributes.getExpires().getEpochSecond()
            // - Instant.now().getEpochSecond());
            responseData.put("issued_token_type", "urn:ietf:params:oauth:token-type:access_token");
            return ResponseModel.mapResponseModel(responseData);

        } catch (Exception e) {
            return ResponseModel.problemResponseModel("token_issuer_exception", "Could not issue new tokens");
        }
    }

    JWTClaimsSet validateJwt(String token) {

        return _validator.validate((token));

    }
}
