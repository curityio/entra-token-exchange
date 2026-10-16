package io.curity.identityserver.plugins.ExternalToken;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.http.HttpResponse;
import se.curity.identityserver.sdk.plugin.ManagedObject;

import java.net.URI;
import java.text.ParseException;

public class JwtValidator extends ManagedObject<ExternalTokenConfig> {
    private static final Logger _logger = LoggerFactory.getLogger(JwtValidator.class);
    private final ExternalTokenConfig _configuration;
    private final ObjectMapper _objectMapper;

    private static final String MICROSOFT_GRAPH_URL = "https://graph.microsoft.com/v1.0/me";

    public JwtValidator(ExternalTokenConfig configuration) {
        super(configuration);
        _configuration = configuration;
        _objectMapper = new ObjectMapper();
    }

    JWTClaimsSet validate(String token) {
        try {
            // First try to parse the JWT to get basic claims for fallback
            SignedJWT jwt = SignedJWT.parse(token);
            JWTClaimsSet originalClaims = jwt.getJWTClaimsSet();

            // Validate token by calling Microsoft Graph API
            HttpResponse response = _configuration.getHttpClient()
                    .request(URI.create(MICROSOFT_GRAPH_URL))
                    .accept("application/json")
                    .header("Authorization", "Bearer " + token)
                    .get()
                    .response();

            int statusCode = response.statusCode();
            String responseBody = response.body(HttpResponse.asString());

            if (statusCode == 200) {
                // Token is valid, parse user information from Graph API response
                JsonNode userInfo = _objectMapper.readTree(responseBody);
                _logger.info("✅ Token valid. User: {}",
                        userInfo.has("userPrincipalName") ? userInfo.get("userPrincipalName").asText()
                                : userInfo.has("mail") ? userInfo.get("mail").asText() : "Unknown");
                _logger.debug("User details from Graph API: {}", responseBody);

                // Return the original JWT claims since validation was successful
                return originalClaims;

            } else if (statusCode == 401) {
                _logger.error("❌ Token invalid or expired (401)");
                throw _configuration.getExceptionFactory().badRequestException(ErrorCode.TOKEN_ISSUANCE_ERROR,
                        "Token invalid or expired");
            } else if (statusCode == 403) {
                _logger.error("🚫 Token valid but lacks required scope (403)");
                throw _configuration.getExceptionFactory().badRequestException(ErrorCode.TOKEN_ISSUANCE_ERROR,
                        "Token valid but lacks required scope");
            } else {
                _logger.error("⚠️ Unexpected status {} from Graph API", statusCode);
                throw _configuration.getExceptionFactory().badRequestException(ErrorCode.TOKEN_ISSUANCE_ERROR,
                        "Unexpected response from validation service");
            }

        } catch (ParseException e) {
            _logger.error("Failed to parse JWT token: {}", e.getMessage());
            throw _configuration.getExceptionFactory().badRequestException(ErrorCode.TOKEN_ISSUANCE_ERROR,
                    "Invalid JWT token format");
        } catch (Exception e) {
            _logger.error("Error calling Graph API for token validation: {}", e.getMessage());
            throw _configuration.getExceptionFactory().badRequestException(ErrorCode.TOKEN_ISSUANCE_ERROR,
                    "Unable to validate token against Microsoft Graph");
        }
    }
}
