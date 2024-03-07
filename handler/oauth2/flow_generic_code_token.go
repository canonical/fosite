// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/fosite/storage"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

// CodeTokenEndpointHandler handles the differences between Authorize code grant and extended grant types.
type CodeTokenEndpointHandler interface {
	// ValidateGrantTypes validates the authorization grant type.
	ValidateGrantTypes(ctx context.Context, requester fosite.AccessRequester) error

	// ValidateCode validates the code used in the authorization flow.
	ValidateCode(ctx context.Context, requester fosite.AccessRequester, code string) error

	// GetCodeAndSession retrieves the code, the code signature, and the request session.
	GetCodeAndSession(ctx context.Context, requester fosite.AccessRequester) (code string, signature string, authorizeRequest fosite.Requester, err error)

	// InvalidateSession invalidates the code once the code is used.
	InvalidateSession(ctx context.Context, signature string) error

	// CanSkipClientAuth indicates if client authentication can be skipped. By default, it MUST be false, unless you are
	// implementing extension grant type, which allows unauthenticated client. CanSkipClientAuth must be called
	// before HandleTokenEndpointRequest to decide, if AccessRequester will contain authenticated client.
	CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool

	// CanHandleTokenEndpointRequest indicates if GenericCodeTokenEndpointHandler can handle this request or not.
	CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool
}

type GenericCodeTokenEndpointHandler struct {
	CodeTokenEndpointHandler

	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	CoreStorage            CoreStorage
	TokenRevocationStorage TokenRevocationStorage
	Config                 interface {
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.RefreshTokenScopesProvider
	}
}

func (c *GenericCodeTokenEndpointHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	code, signature, ar, err := c.GetCodeAndSession(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err = c.ValidateCode(ctx, requester, code); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range ar.GetRequestedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range ar.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	accessToken, accessTokenSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refreshToken, refreshTokenSignature string
	if c.canIssueRefreshToken(ctx, ar) {
		refreshToken, refreshTokenSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	if err = c.InvalidateSession(ctx, signature); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessTokenSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if refreshTokenSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshTokenSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	lifeSpan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, lifeSpan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refreshToken != "" {
		responder.SetExtra("refresh_token", refreshToken)
	}

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (c *GenericCodeTokenEndpointHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	if err := c.ValidateGrantTypes(ctx, requester); err != nil {
		return err
	}

	code, _, ar, err := c.GetCodeAndSession(ctx, requester)
	if err != nil {
		switch {
		case errors.Is(err, fosite.ErrInvalidatedAuthorizeCode), errors.Is(err, fosite.ErrInvalidatedDeviceCode):
			if ar == nil {
				return fosite.ErrServerError.
					WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
					WithDebug("getCodeSession must return a value for \"fosite.Requester\" when returning \"ErrInvalidatedAuthorizeCode\" or \"ErrInvalidatedDeviceCode\".")
			}

			return c.revokeTokens(ctx, requester.GetID())
		case errors.Is(err, fosite.ErrAuthorizationPending):
			return err
		case errors.Is(err, fosite.ErrPollingRateLimited):
			return errorsx.WithStack(err)
		case errors.Is(err, fosite.ErrNotFound):
			return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
		default:
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	if err = c.ValidateCode(ctx, requester, code); err != nil {
		return errorsx.WithStack(err)
	}

	// Override scopes
	requester.SetRequestedScopes(ar.GetRequestedScopes())

	// Override audiences
	requester.SetRequestedAudience(ar.GetRequestedAudience())

	// The authorization server MUST ensure that
	// the authorization code was issued to the authenticated confidential client,
	// or if the client is public, ensure that the code was issued to "client_id" in the request
	if ar.GetClient().GetID() != requester.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	forcedRedirectURI := ar.GetRequestForm().Get("redirect_uri")
	requestedRedirectURI := requester.GetRequestForm().Get("redirect_uri")
	if forcedRedirectURI != "" && forcedRedirectURI != requestedRedirectURI {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The \"redirect_uri\" from this request does not match the one from the authorize request."))
	}

	// Checking of POST client_id skipped, because
	// if the client type is confidential or the client was issued client credentials (or assigned other authentication requirements),
	// the client MUST authenticate with the authorization server as described in Section 3.2.1.
	requester.SetSession(ar.GetSession())
	requester.SetID(ar.GetID())

	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	requester.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		requester.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func (c *GenericCodeTokenEndpointHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return c.CodeTokenEndpointHandler.CanSkipClientAuth(ctx, requester)
}

func (c *GenericCodeTokenEndpointHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return c.CodeTokenEndpointHandler.CanHandleTokenEndpointRequest(ctx, requester)
}

func (c *GenericCodeTokenEndpointHandler) canIssueRefreshToken(ctx context.Context, requester fosite.Requester) bool {
	scope := c.Config.GetRefreshTokenScopes(ctx)
	if len(scope) > 0 && !requester.GetGrantedScopes().HasOneOf(scope...) {
		return false
	}

	if !requester.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}

	return true
}

func (c *GenericCodeTokenEndpointHandler) revokeTokens(ctx context.Context, reqId string) error {
	hint := "The authorization code has already been used."
	var debug strings.Builder

	revokeAndAppendErr := func(tokenType string, revokeFunc func(context.Context, string) error) {
		if err := revokeFunc(ctx, reqId); err != nil {
			hint += fmt.Sprintf(" Additionally, an error occurred during processing the %s token revocation.", tokenType)
			debug.WriteString(fmt.Sprintf("Revocation of %s token lead to error %s.", tokenType, err.Error()))
		}
	}

	revokeAndAppendErr("access", c.TokenRevocationStorage.RevokeAccessToken)
	revokeAndAppendErr("refresh", c.TokenRevocationStorage.RevokeRefreshToken)

	return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(hint).WithDebug(debug.String()))
}

var _ fosite.TokenEndpointHandler = (*GenericCodeTokenEndpointHandler)(nil)
