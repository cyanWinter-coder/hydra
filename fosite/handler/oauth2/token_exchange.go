package oauth2

import (
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/x/errorsx"
)

var _ fosite.TokenEndpointHandler = (*TokenExchangeGrantHandler)(nil)

// TokenExchangeStorage records subject tokens that were already consumed by a
// token exchange. Implementations must make the operation atomic and return
// fosite.ErrJTIKnown when the same token is consumed more than once.
type TokenExchangeStorage interface {
	MarkTokenExchangeSubjectTokenUsed(ctx context.Context, tokenType, signature string, expiresAt time.Time) error
}

type TokenExchangeStorageProvider interface {
	TokenExchangeStorage() TokenExchangeStorage
}

// TokenExchangeConfigProvider exposes the policy knobs for RFC 8693 token
// exchange. Implementations that do not provide these values use secure
// defaults in the handler.
type TokenExchangeConfigProvider interface {
	GetTokenExchangeEnabled(ctx context.Context) bool
	GetTokenExchangeAllowCrossClient(ctx context.Context) bool
	GetTokenExchangeRequireActor(ctx context.Context) bool
	GetTokenExchangeAllowedSubjectTokenTypes(ctx context.Context) []string
	GetTokenExchangeAllowedActorTokenTypes(ctx context.Context) []string
}

// TokenExchangeGrantHandler implements RFC 8693 OAuth 2.0 Token Exchange.
type TokenExchangeGrantHandler struct {
	Storage interface {
		fosite.Transactional
		AccessTokenStorageProvider
		TokenRevocationStorageProvider
		TokenExchangeStorageProvider
	}
	Strategy AccessTokenStrategyProvider
	Config   interface {
		fosite.AccessTokenLifespanProvider
		fosite.AccessTokenIssuerProvider
		fosite.ScopeStrategyProvider
		fosite.AudienceStrategyProvider
		TokenExchangeConfigProvider
	}
}

type tokenExchangeIssuerSession interface {
	GetAccessTokenIssuer() string
}

type tokenExchangeActorSession interface {
	SetTokenExchangeActor(subject string)
}

// HandleTokenEndpointRequest validates the exchanged tokens and applies the
// client's scope and audience policy. The actual one-time consumption of the
// subject token happens in PopulateTokenEndpointResponse, inside the caller's
// storage transaction.
func (c *TokenExchangeGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	client := request.GetClient()
	if !c.Config.GetTokenExchangeEnabled(ctx) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint(
			"OAuth 2.0 Token Exchange is disabled by the authorization server configuration.",
		))
	}
	if !client.GetGrantTypes().Has(string(fosite.GrantTypeTokenExchange)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHintf(
			"The OAuth 2.0 Client '%s' is not allowed to use authorization grant '%s'.",
			client.GetID(), fosite.GrantTypeTokenExchange,
		))
	}

	if c.Config.GetTokenExchangeRequireActor(ctx) && request.GetRequestForm().Get("actor_token") == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"Token exchange is configured to require an 'actor_token', but the parameter is missing.",
		))
	}

	subjectToken, err := requiredTokenExchangeParameter(request, "subject_token")
	if err != nil {
		return err
	}
	subjectTokenType, err := requiredTokenExchangeParameter(request, "subject_token_type")
	if err != nil {
		return err
	}
	if !containsString(c.Config.GetTokenExchangeAllowedSubjectTokenTypes(ctx), subjectTokenType) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
			"Unsupported 'subject_token_type' %q for token exchange.", subjectTokenType,
		))
	}
	if err := validateTokenTypeFormat(subjectTokenType, subjectToken, "subject_token"); err != nil {
		return err
	}

	actorToken, actorTokenType, err := optionalTokenExchangeActor(request)
	if err != nil {
		return err
	}
	if actorToken != "" && !containsString(c.Config.GetTokenExchangeAllowedActorTokenTypes(ctx), actorTokenType) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
			"Unsupported 'actor_token_type' %q for token exchange.", actorTokenType,
		))
	}
	if actorToken != "" {
		if err := validateTokenTypeFormat(actorTokenType, actorToken, "actor_token"); err != nil {
			return err
		}
	}

	if _, err := issuedTokenType(request); err != nil {
		return err
	}

	subjectRequest, subjectSession, err := c.loadSubjectToken(ctx, subjectToken, subjectTokenType, "subject_token", request.GetSession())
	if err != nil {
		return err
	}

	if !c.Config.GetTokenExchangeAllowCrossClient(ctx) && subjectRequest.GetClient().GetID() != client.GetID() {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHintf(
			"Cross-client token exchange is disabled. The subject token was issued to client '%s', but the request was authenticated by client '%s'.",
			subjectRequest.GetClient().GetID(), client.GetID(),
		))
	}

	var actorSession fosite.Session
	if actorToken != "" {
		actorRequest, session, err := c.loadSubjectToken(ctx, actorToken, actorTokenType, "actor_token", request.GetSession())
		if err != nil {
			return err
		}
		if !c.Config.GetTokenExchangeAllowCrossClient(ctx) && actorRequest.GetClient().GetID() != client.GetID() {
			return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHintf(
				"Cross-client token exchange is disabled. The actor token was issued to client '%s', but the request was authenticated by client '%s'.",
				actorRequest.GetClient().GetID(), client.GetID(),
			))
		}
		actorSession = session
	}

	if err := c.applyScopes(ctx, request, subjectRequest.GetGrantedScopes()); err != nil {
		return err
	}
	if err := c.applyAudiences(ctx, request, subjectRequest.GetGrantedAudience()); err != nil {
		return err
	}

	resultSession := subjectSession.Clone()
	if resultSession == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithHint("The subject token session could not be cloned."))
	}
	if extra, ok := resultSession.(fosite.ExtraClaimsSession); ok {
		for key := range extra.GetExtraClaims() {
			delete(extra.GetExtraClaims(), key)
		}
	}
	if setter, ok := resultSession.(interface{ SetSubject(string) }); ok {
		setter.SetSubject(subjectSession.GetSubject())
	}
	if actorSession != nil {
		if setter, ok := resultSession.(tokenExchangeActorSession); ok {
			setter.SetTokenExchangeActor(actorSession.GetSubject())
		} else if extra, ok := resultSession.(fosite.ExtraClaimsSession); ok {
			extra.GetExtraClaims()["act"] = map[string]interface{}{"sub": actorSession.GetSubject()}
		}
	}

	expiresAt := time.Now().UTC().Add(fosite.GetEffectiveLifespan(
		client,
		fosite.GrantTypeTokenExchange,
		fosite.AccessToken,
		c.Config.GetAccessTokenLifespan(ctx),
	)).Round(time.Second)
	for _, session := range []fosite.Session{subjectSession, actorSession} {
		if session == nil {
			continue
		}
		if exp := session.GetExpiresAt(fosite.AccessToken); !exp.IsZero() && exp.Before(expiresAt) {
			expiresAt = exp
		}
	}
	resultSession.SetExpiresAt(fosite.AccessToken, expiresAt)

	request.SetID(subjectRequest.GetID())
	request.SetSession(resultSession)
	return nil
}

func (c *TokenExchangeGrantHandler) loadSubjectToken(
	ctx context.Context,
	token string,
	tokenType string,
	parameter string,
	workingSession fosite.Session,
) (fosite.Requester, fosite.Session, error) {
	strategy := c.Strategy.AccessTokenStrategy()
	signature := strategy.AccessTokenSignature(ctx, token)
	original, err := c.Storage.AccessTokenStorage().GetAccessTokenSession(ctx, signature, workingSession)
	if errors.Is(err, fosite.ErrNotFound) || errors.Is(err, fosite.ErrInactiveToken) {
		return nil, nil, errorsx.WithStack(fosite.ErrInvalidGrant.
			WithWrap(err).
			WithHintf("The '%s' is invalid, expired, or revoked.", parameter).
			WithDebugf("Could not load %s of type %q: %s", parameter, tokenType, err))
	} else if err != nil {
		return nil, nil, errorsx.WithStack(fosite.ErrServerError.
			WithWrap(err).
			WithHintf("The '%s' could not be loaded.", parameter).
			WithDebugf("Could not load %s of type %q: %s", parameter, tokenType, err))
	}

	if err := strategy.ValidateAccessToken(ctx, original, token); err != nil {
		return nil, nil, errorsx.WithStack(fosite.ErrInvalidGrant.
			WithWrap(err).
			WithHintf("The '%s' failed validation.", parameter).
			WithDebugf("Validation of %s of type %q failed: %s", parameter, tokenType, err))
	}

	session := original.GetSession()
	if session == nil {
		return nil, nil, errorsx.WithStack(fosite.ErrServerError.
			WithHintf("The '%s' session is missing.", parameter))
	}
	if issuerSession, ok := session.(tokenExchangeIssuerSession); ok {
		expected := c.Config.GetAccessTokenIssuer(ctx)
		actual := issuerSession.GetAccessTokenIssuer()
		if expected != "" && actual != expected {
			return nil, nil, errorsx.WithStack(fosite.ErrInvalidGrant.WithHintf(
				"The '%s' was issued by %q, not by this authorization server %q.",
				parameter, actual, expected,
			))
		}
	}

	return original, session.Clone(), nil
}

func (c *TokenExchangeGrantHandler) applyScopes(ctx context.Context, request fosite.AccessRequester, subjectScopes fosite.Arguments) error {
	client := request.GetClient()
	scopeStrategy := c.Config.GetScopeStrategy(ctx)
	requested := request.GetRequestedScopes()
	if len(requested) == 0 {
		for _, scope := range subjectScopes {
			if scopeStrategy(client.GetScopes(), scope) {
				request.GrantScope(scope)
			}
		}
		return nil
	}

	for _, scope := range requested {
		if !scopeStrategy(client.GetScopes(), scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf(
				"The OAuth 2.0 Client '%s' is not allowed to request scope '%s' for token exchange.",
				client.GetID(), scope,
			))
		}
		if !scopeStrategy(subjectScopes, scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf(
				"Requested scope '%s' is not present in the subject token.",
				scope,
			))
		}
		request.GrantScope(scope)
	}
	return nil
}

func (c *TokenExchangeGrantHandler) applyAudiences(ctx context.Context, request fosite.AccessRequester, subjectAudiences fosite.Arguments) error {
	client := request.GetClient()
	audienceStrategy := c.Config.GetAudienceStrategy(ctx)
	requested := request.GetRequestedAudience()
	if len(requested) == 0 {
		for _, audience := range subjectAudiences {
			if audienceStrategy(client.GetAudience(), []string{audience}) == nil {
				request.GrantAudience(audience)
			}
		}
		return nil
	}

	if err := audienceStrategy(client.GetAudience(), requested); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.
			WithWrap(err).
			WithHintf("The OAuth 2.0 Client '%s' is not allowed to request the supplied audience for token exchange.", client.GetID()).
			WithDebug(err.Error()))
	}
	if err := audienceStrategy(subjectAudiences, requested); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.
			WithWrap(err).
			WithHint("The requested audience is not present in the subject token.").
			WithDebug(err.Error()))
	}
	for _, audience := range requested {
		request.GrantAudience(audience)
	}
	return nil
}

// PopulateTokenEndpointResponse consumes the subject token and issues the
// exchanged access token.
func (c *TokenExchangeGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	subjectToken := requester.GetRequestForm().Get("subject_token")
	subjectTokenType := requester.GetRequestForm().Get("subject_token_type")
	issuedType, err := issuedTokenType(requester)
	if err != nil {
		return err
	}

	signature := c.Strategy.AccessTokenStrategy().AccessTokenSignature(ctx, subjectToken)
	expiresAt := requester.GetSession().GetExpiresAt(fosite.AccessToken)
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(c.Config.GetAccessTokenLifespan(ctx))
	}
	// The input token type URNs are aliases for Hydra access tokens. Use one
	// canonical replay key so clients cannot bypass detection by switching the
	// declared type between access_token and jwt.
	if err := c.Storage.TokenExchangeStorage().MarkTokenExchangeSubjectTokenUsed(ctx, string(fosite.AccessToken), signature, expiresAt); err != nil {
		if errors.Is(err, fosite.ErrJTIKnown) || errors.Is(err, fosite.ErrInvalidGrant) {
			return errorsx.WithStack(fosite.ErrInvalidGrant.
				WithWrap(err).
				WithHint("The subject token was already used in a token exchange.").
				WithDebugf("Replay detected for subject token type %q.", subjectTokenType))
		}
		return errorsx.WithStack(fosite.ErrServerError.
			WithWrap(err).
			WithHint("The subject token could not be marked as used.").
			WithDebug(err.Error()))
	}

	accessToken, accessSignature, err := c.Strategy.AccessTokenStrategy().GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	if err := c.Storage.AccessTokenStorage().CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType(fosite.BearerAccessToken)
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx), time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	responder.SetExtra("issued_token_type", string(issuedType))
	return nil
}

func (c *TokenExchangeGrantHandler) CanSkipClientAuth(context.Context, fosite.AccessRequester) bool {
	return false
}

func (c *TokenExchangeGrantHandler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeTokenExchange))
}

func requiredTokenExchangeParameter(request fosite.AccessRequester, name string) (string, error) {
	values, ok := request.GetRequestForm()[name]
	if !ok || len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
			"Token exchange requires the '%s' parameter.", name,
		))
	}
	if len(values) > 1 {
		return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
			"Token exchange parameter '%s' must not be included more than once.", name,
		))
	}
	return strings.TrimSpace(values[0]), nil
}

func optionalTokenExchangeActor(request fosite.AccessRequester) (token, tokenType string, err error) {
	values, present := request.GetRequestForm()["actor_token"]
	if present && len(values) > 1 {
		return "", "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"Token exchange parameter 'actor_token' must not be included more than once.",
		))
	}
	if len(values) == 1 {
		token = strings.TrimSpace(values[0])
	}

	typeValues, typePresent := request.GetRequestForm()["actor_token_type"]
	if typePresent && len(typeValues) > 1 {
		return "", "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"Token exchange parameter 'actor_token_type' must not be included more than once.",
		))
	}
	if len(typeValues) == 1 {
		tokenType = strings.TrimSpace(typeValues[0])
	}

	if token != "" && tokenType == "" {
		return "", "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"Token exchange requires 'actor_token_type' when 'actor_token' is present.",
		))
	}
	if token == "" && tokenType != "" {
		return "", "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"Token exchange requires 'actor_token' when 'actor_token_type' is present.",
		))
	}
	return token, tokenType, nil
}

func issuedTokenType(request fosite.AccessRequester) (fosite.TokenType, error) {
	values, ok := request.GetRequestForm()["requested_token_type"]
	if ok && len(values) > 1 {
		return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHint(
			"Token exchange parameter 'requested_token_type' must not be included more than once.",
		))
	}
	if !ok || len(values) == 0 || strings.TrimSpace(values[0]) == "" {
		return fosite.TokenTypeAccessTokenURN, nil
	}
	requested := fosite.TokenType(strings.TrimSpace(values[0]))
	switch requested {
	case fosite.TokenTypeAccessTokenURN, fosite.TokenTypeJWTURN:
		return requested, nil
	default:
		return "", errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
			"Unsupported 'requested_token_type' %q. Supported values are %q and %q.",
			requested, fosite.TokenTypeAccessTokenURN, fosite.TokenTypeJWTURN,
		))
	}
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func validateTokenTypeFormat(tokenType, token, parameter string) error {
	if fosite.TokenType(tokenType) != fosite.TokenTypeJWTURN {
		return nil
	}
	if parts := strings.Split(token, "."); len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
			"The '%s' is declared as %q but is not a compact JWT.",
			parameter, fosite.TokenTypeJWTURN,
		))
	}
	return nil
}
