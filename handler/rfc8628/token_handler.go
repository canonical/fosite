package rfc8628

import (
	"context"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

// DeviceTokenHandler is a token response handler for the Device Code introduced in the Device Authorize Grant
// as defined in https://www.rfc-editor.org/rfc/rfc8628
type DeviceTokenHandler struct {
	DeviceRateLimitStrategy DeviceRateLimitStrategy
	DeviceCodeStrategy      DeviceCodeStrategy
	DeviceCodeStorage       DeviceCodeStorage
}

func (c DeviceTokenHandler) ValidateGrantTypes(ctx context.Context, requester fosite.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:device_code\"."))
	}

	return nil
}

func (c DeviceTokenHandler) ValidateCode(ctx context.Context, requester fosite.AccessRequester, code string) error {
	return c.DeviceCodeStrategy.ValidateDeviceCode(ctx, requester, code)
}

func (c DeviceTokenHandler) GetCodeAndSession(ctx context.Context, requester fosite.AccessRequester) (code string, signature string, authorizeRequest fosite.Requester, err error) {
	code = requester.GetRequestForm().Get("device_code")

	if c.DeviceRateLimitStrategy.ShouldRateLimit(ctx, code) {
		return "", "", nil, fosite.ErrPollingRateLimited
	}

	signature, err = c.DeviceCodeStrategy.DeviceCodeSignature(ctx, code)
	if err != nil {
		return "", "", nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	req, err := c.DeviceCodeStorage.GetDeviceCodeSession(ctx, signature, requester.GetSession())
	if err != nil {
		return "", "", nil, err
	}

	return code, signature, req, nil
}

func (c DeviceTokenHandler) InvalidateSession(ctx context.Context, signature string) error {
	return c.DeviceCodeStorage.InvalidateDeviceCodeSession(ctx, signature)
}

func (c DeviceTokenHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

func (c DeviceTokenHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

type DeviceCodeTokenEndpointHandler struct {
	oauth2.GenericCodeTokenEndpointHandler
}

var (
	_ oauth2.CodeTokenEndpointHandler = (*DeviceTokenHandler)(nil)
	_ fosite.TokenEndpointHandler     = (*DeviceCodeTokenEndpointHandler)(nil)
)
