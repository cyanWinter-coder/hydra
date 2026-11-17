package oauth2_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	goauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/x/configx"
)

const tokenExchangeType = "urn:ietf:params:oauth:grant-type:token-exchange"

type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

func TestTokenExchange(t *testing.T) {
	ctx := context.Background()
	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(configx.WithValue(config.KeyAccessTokenStrategy, "jwt")))
	public, admin := testhelpers.NewOAuth2Server(ctx, t, reg)

	audience := "https://api.example.com/"
	createClient := func(t *testing.T, id string, grants []string, scope string, audiences []string) *client.Client {
		secret := uuid.Must(uuid.NewV4()).String()
		cl := &client.Client{
			ID:                      id,
			Secret:                  secret,
			RedirectURIs:            []string{public.URL + "/callback"},
			ResponseTypes:           []string{"token"},
			GrantTypes:              grants,
			Scope:                   scope,
			Audience:                audiences,
			TokenEndpointAuthMethod: "client_secret_basic",
		}
		require.NoError(t, reg.ClientManager().CreateClient(ctx, cl))
		cl.Secret = secret
		return cl
	}

	subjectClient := createClient(t, "token-exchange-subject-"+uuid.Must(uuid.NewV4()).String(), []string{"client_credentials"}, "read write", []string{audience})
	actorClient := createClient(t, "token-exchange-actor-"+uuid.Must(uuid.NewV4()).String(), []string{"client_credentials"}, "act", []string{audience})
	exchangeClient := createClient(t, "token-exchange-client-"+uuid.Must(uuid.NewV4()).String(), []string{tokenExchangeType}, "read", []string{audience})
	unauthorizedClient := createClient(t, "token-exchange-unauthorized-"+uuid.Must(uuid.NewV4()).String(), []string{"client_credentials"}, "read", []string{audience})

	getClientToken := func(t *testing.T, cl *client.Client, scopes []string) string {
		conf := clientcredentials.Config{
			ClientID:       cl.ID,
			ClientSecret:   cl.Secret,
			TokenURL:       public.URL + "/oauth2/token",
			Scopes:         scopes,
			EndpointParams: url.Values{"audience": {audience}},
			AuthStyle:      goauth2.AuthStyleInHeader,
		}
		token, err := conf.Token(ctx)
		require.NoError(t, err)
		return token.AccessToken
	}

	exchange := func(t *testing.T, cl *client.Client, params url.Values) (int, gjson.Result) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, public.URL+"/oauth2/token", strings.NewReader(params.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(cl.ID, cl.Secret)

		res, err := public.Client().Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		return res.StatusCode, gjson.ParseBytes(body)
	}

	baseParams := func(subjectToken, actorToken string) url.Values {
		params := url.Values{
			"grant_type":         {tokenExchangeType},
			"subject_token":      {subjectToken},
			"subject_token_type": {string(fosite.TokenTypeAccessTokenURN)},
			"scope":              {"read"},
			"audience":           {audience},
		}
		if actorToken != "" {
			params.Set("actor_token", actorToken)
			params.Set("actor_token_type", string(fosite.TokenTypeAccessTokenURN))
		}
		return params
	}

	t.Run("case=exchanges subject and actor tokens with narrowed scope", func(t *testing.T) {
		subjectToken := getClientToken(t, subjectClient, []string{"read", "write"})
		actorToken := getClientToken(t, actorClient, []string{"act"})

		status, body := exchange(t, exchangeClient, baseParams(subjectToken, actorToken))
		require.Equal(t, http.StatusOK, status, body.Raw)

		var response tokenExchangeResponse
		require.NoError(t, json.Unmarshal([]byte(body.Raw), &response))
		assert.Equal(t, "read", response.Scope)
		assert.Equal(t, "bearer", response.TokenType)
		assert.Equal(t, string(fosite.TokenTypeAccessTokenURN), response.IssuedTokenType)
		require.NotEmpty(t, response.AccessToken)

		claims := gjson.ParseBytes(testhelpers.InsecureDecodeJWT(t, response.AccessToken))
		assert.Equal(t, subjectClient.ID, claims.Get("sub").String(), claims.Raw)
		assert.Equal(t, exchangeClient.ID, claims.Get("client_id").String(), claims.Raw)
		assert.Equal(t, reg.Config().IssuerURL(ctx).String(), claims.Get("iss").String(), claims.Raw)
		assert.Equal(t, actorClient.ID, claims.Get("act.sub").String(), claims.Raw)
		assert.Equal(t, audience, claims.Get("aud.0").String(), claims.Raw)
		assert.Equal(t, `["read"]`, claims.Get("scp").Raw, claims.Raw)

		introspection := testhelpers.IntrospectToken(t, response.AccessToken, admin)
		assert.True(t, introspection.Get("active").Bool(), introspection.Raw)
		assert.Equal(t, subjectClient.ID, introspection.Get("sub").String(), introspection.Raw)
		assert.Equal(t, actorClient.ID, introspection.Get("act.sub").String(), introspection.Raw)
	})

	t.Run("case=rejects invalid audiences scopes and clients", func(t *testing.T) {
		subjectToken := getClientToken(t, subjectClient, []string{"read"})

		params := baseParams(subjectToken, "")
		params.Set("audience", "https://not-allowed.example.com/")
		status, body := exchange(t, exchangeClient, params)
		assert.Equal(t, http.StatusBadRequest, status, body.Raw)
		assert.Equal(t, "invalid_request", body.Get("error").String(), body.Raw)

		params = baseParams(subjectToken, "")
		params.Set("scope", "write")
		status, body = exchange(t, exchangeClient, params)
		assert.Equal(t, http.StatusBadRequest, status, body.Raw)
		assert.Equal(t, "invalid_scope", body.Get("error").String(), body.Raw)

		status, body = exchange(t, unauthorizedClient, baseParams(subjectToken, ""))
		assert.Equal(t, http.StatusBadRequest, status, body.Raw)
		assert.Equal(t, "unauthorized_client", body.Get("error").String(), body.Raw)
	})

	t.Run("case=detects replay and revokes derived tokens with the source session", func(t *testing.T) {
		subjectToken := getClientToken(t, subjectClient, []string{"read"})
		params := baseParams(subjectToken, "")

		status, body := exchange(t, exchangeClient, params)
		require.Equal(t, http.StatusOK, status, body.Raw)
		derivedToken := body.Get("access_token").String()

		status, body = exchange(t, exchangeClient, params)
		assert.Equal(t, http.StatusBadRequest, status, body.Raw)
		assert.Equal(t, "invalid_grant", body.Get("error").String(), body.Raw)

		params.Set("subject_token_type", string(fosite.TokenTypeJWTURN))
		status, body = exchange(t, exchangeClient, params)
		assert.Equal(t, http.StatusBadRequest, status, body.Raw)
		assert.Equal(t, "invalid_grant", body.Get("error").String(), body.Raw)
		params.Set("subject_token_type", string(fosite.TokenTypeAccessTokenURN))

		revoke := func(t *testing.T, token string) {
			body := url.Values{"token": {token}}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, public.URL+"/oauth2/revoke", strings.NewReader(body.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(subjectClient.ID, subjectClient.Secret)
			res, err := public.Client().Do(req)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())
			require.Equal(t, http.StatusOK, res.StatusCode)
		}
		revoke(t, subjectToken)

		introspection := testhelpers.IntrospectToken(t, derivedToken, admin)
		assert.False(t, introspection.Get("active").Bool(), introspection.Raw)

		freshSubjectToken := getClientToken(t, subjectClient, []string{"read"})
		params = baseParams(freshSubjectToken, "")
		status, body = exchange(t, exchangeClient, params)
		require.Equal(t, http.StatusOK, status, body.Raw)
		freshDerivedToken := body.Get("access_token").String()
		revoke(t, freshSubjectToken)
		introspection = testhelpers.IntrospectToken(t, freshDerivedToken, admin)
		assert.False(t, introspection.Get("active").Bool(), introspection.Raw)

		status, body = exchange(t, exchangeClient, params)
		assert.Equal(t, http.StatusBadRequest, status, body.Raw)
		assert.Equal(t, "invalid_grant", body.Get("error").String(), body.Raw)
	})

	t.Run("case=allows exactly one concurrent exchange for the same subject token", func(t *testing.T) {
		subjectToken := getClientToken(t, subjectClient, []string{"read"})

		const attempts = 8
		statuses := make(chan int, attempts)
		var wg sync.WaitGroup
		for range attempts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				params := baseParams(subjectToken, "")
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, public.URL+"/oauth2/token", strings.NewReader(params.Encode()))
				if err != nil {
					statuses <- 0
					return
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth(exchangeClient.ID, exchangeClient.Secret)
				res, err := public.Client().Do(req)
				if err != nil {
					statuses <- 0
					return
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				statuses <- res.StatusCode
			}()
		}
		wg.Wait()
		close(statuses)

		var successes, rejected int
		for status := range statuses {
			switch status {
			case http.StatusOK:
				successes++
			case http.StatusBadRequest:
				rejected++
			default:
				t.Errorf("unexpected token exchange status: %d", status)
			}
		}
		assert.Equal(t, 1, successes)
		assert.Equal(t, attempts-1, rejected)
	})

	t.Run("case=keeps authorization code and refresh token grants available", func(t *testing.T) {
		discovery := gjson.ParseBytes(func() []byte {
			res, err := public.Client().Get(public.URL + "/.well-known/openid-configuration")
			require.NoError(t, err)
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			return body
		}())
		assert.True(t, discovery.Get("grant_types_supported").Array() != nil)
		assert.Contains(t, discovery.Get("grant_types_supported").Raw, "authorization_code")
		assert.Contains(t, discovery.Get("grant_types_supported").Raw, "refresh_token")
		assert.Contains(t, discovery.Get("grant_types_supported").Raw, tokenExchangeType)
	})

	t.Run("case=supports opaque access tokens", func(t *testing.T) {
		reg.Config().MustSet(ctx, config.KeyAccessTokenStrategy, "opaque")
		t.Cleanup(func() { reg.Config().MustSet(ctx, config.KeyAccessTokenStrategy, "jwt") })

		subjectToken := getClientToken(t, subjectClient, []string{"read"})
		status, body := exchange(t, exchangeClient, baseParams(subjectToken, ""))
		require.Equal(t, http.StatusOK, status, body.Raw)

		introspection := testhelpers.IntrospectToken(t, body.Get("access_token").String(), admin)
		assert.True(t, introspection.Get("active").Bool(), introspection.Raw)
		assert.Equal(t, subjectClient.ID, introspection.Get("sub").String(), introspection.Raw)
		assert.Equal(t, "read", introspection.Get("scope").String(), introspection.Raw)
	})

	t.Run("case=respects server policy switches", func(t *testing.T) {
		reg.Config().MustSet(ctx, config.KeyTokenExchangeAllowCrossClient, false)
		t.Cleanup(func() { reg.Config().MustSet(ctx, config.KeyTokenExchangeAllowCrossClient, true) })

		status, body := exchange(t, exchangeClient, baseParams(getClientToken(t, subjectClient, []string{"read"}), ""))
		assert.Equal(t, http.StatusBadRequest, status, body.Raw)
		assert.Equal(t, "unauthorized_client", body.Get("error").String(), body.Raw)

		reg.Config().MustSet(ctx, config.KeyTokenExchangeAllowCrossClient, true)
		reg.Config().MustSet(ctx, config.KeyTokenExchangeEnabled, false)
		t.Cleanup(func() { reg.Config().MustSet(ctx, config.KeyTokenExchangeEnabled, true) })

		status, body = exchange(t, exchangeClient, baseParams(getClientToken(t, subjectClient, []string{"read"}), ""))
		assert.Equal(t, http.StatusBadRequest, status, body.Raw)
		assert.Equal(t, "unauthorized_client", body.Get("error").String(), body.Raw)
	})
}
