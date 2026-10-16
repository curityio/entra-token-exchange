# Entra Token Exchange Plugin

This is a Curity token exchange plugin that validates Microsoft Entra ID (Azure AD) tokens using the Microsoft Graph API instead of JWT signature validation.

## Building

```bash
mvn clean package
```

## Usage
Deploy the built JAR to your Curity Identity Server plugins directory and configure as a token exchange procedure.

### Example

Send a token exchange request to the `oauth-token` endpoint with an Entra ID access token as the `subject_token`. The token must be accepted by Microsoft Graph (audience `https://graph.microsoft.com` with the `User.Read` scope), since the plugin validates it by calling `/me`.

```bash
curl -Ss -X POST \
  https://idsvr.example.com/oauth/v2/oauth-token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d 'client_id=my-client' \
  -d 'client_secret=my-client-secret' \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  -d 'subject_token=<entra-access-token>'
```

If the token is valid, the response contains a new access token issued by the Curity Identity Server, with the subject taken from the Entra token's `sub` claim:

```json
{
  "access_token": "eyJraWQiOi...",
  "token_type": "bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

If the token can't be validated against Microsoft Graph, the request fails with a `400` error.
