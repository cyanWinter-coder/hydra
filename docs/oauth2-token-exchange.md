# OAuth 2.0 Token Exchange

Hydra implements RFC 8693 token exchange at `POST /oauth2/token`. Token
exchange uses the standard OAuth 2.0 client authentication methods and is
available only to clients that explicitly list the grant type:

```json
{
  "grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange"],
  "scope": "read",
  "audience": ["https://api.example.com/"]
}
```

## Request

Send an `application/x-www-form-urlencoded` request with the following
parameters:

| Parameter            | Required | Description                                                                                                    |
| -------------------- | -------- | -------------------------------------------------------------------------------------------------------------- |
| `grant_type`         | yes      | Must be `urn:ietf:params:oauth:grant-type:token-exchange`.                                                     |
| `subject_token`      | yes      | Access token whose subject is being delegated.                                                                |
| `subject_token_type` | yes      | `urn:ietf:params:oauth:token-type:access_token` or `urn:ietf:params:oauth:token-type:jwt`.                      |
| `actor_token`        | no       | Access token identifying the acting party.                                                                     |
| `actor_token_type`   | no       | Required when `actor_token` is present; same values as `subject_token_type`.                                   |
| `scope`              | no       | Space-delimited subset of the subject token's granted scopes. Defaults to the subject token's permitted scopes. |
| `audience`           | no       | One or more target audiences. Repeated parameters and space-delimited values are supported.                    |
| `requested_token_type` | no     | `urn:ietf:params:oauth:token-type:access_token` (default) or `urn:ietf:params:oauth:token-type:jwt`.          |

Example:

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=$SUBJECT_TOKEN" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "actor_token=$ACTOR_TOKEN" \
  --data-urlencode "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "scope=read" \
  --data-urlencode "audience=https://api.example.com/" \
  https://hydra.example.com/oauth2/token
```

The access token response contains `access_token`, `issued_token_type`,
`token_type`, `expires_in`, and the narrowed `scope`. JWT access tokens carry
the delegated subject in `sub`, the acting party in `act.sub`, and the target
audiences in `aud`.

## Validation and lifecycle

- Subject and actor tokens must be active, unexpired, stored by this Hydra
  instance, and issued by the configured issuer.
- Requested scopes must be granted by the subject token and allowed by the
  requesting client.
- Requested audiences must be present in the subject token and allowed by the
  requesting client.
- An exchanged token never outlives its subject or actor token.
- The exchanged token inherits the subject token's request ID. Revoking the
  subject token or its session also revokes tokens derived from it.
- A subject token can be consumed only once. Concurrent attempts are serialized;
  exactly one succeeds and the others receive `invalid_grant`.

## Configuration

Defaults are shown below:

```yaml
oauth2:
  grant:
    token_exchange:
      enabled: true
      allow_cross_client: true
      require_actor: false
      subject_token_types:
        - urn:ietf:params:oauth:token-type:access_token
        - urn:ietf:params:oauth:token-type:jwt
      actor_token_types:
        - urn:ietf:params:oauth:token-type:access_token
        - urn:ietf:params:oauth:token-type:jwt
```

Set `allow_cross_client` to `false` to require that both subject and actor
tokens were issued to the client performing the exchange.

## Tests

Run the token exchange integration test:

```bash
go test ./oauth2 -run '^TestTokenExchange$' -count=1
```

Run the relevant protocol, storage, and OAuth2 suites:

```bash
go test ./fosite/... ./oauth2 ./driver/config ./persistence/sql
```

## Known limitations

- Subject and actor tokens are currently access tokens (opaque or JWT access
  tokens). ID tokens, refresh tokens, SAML assertions, and external-issuer
  tokens are not accepted as exchange inputs.
- Token exchange issues access tokens only. Refresh tokens are not issued by
  this grant.
- Actor delegation is represented by a single `act.sub` claim. Existing nested
  actor chains from the actor token are not copied.
- The replay marker is network-scoped and retained until the consumed subject
  token expires.
- Policy is expressed through client scopes, client audiences, grant types, and
  the `oauth2.grant.token_exchange` settings. There is no per-pair client
  allow-list beyond `allow_cross_client`.
