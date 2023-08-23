package supabase

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const AuthEndpoint = "auth/v1"

type Client struct {
	BaseURL    string
	apiKey     string
	HTTPClient *http.Client
}

func NewClient(baseURL string, supabaseKey string) *Client {
	client := &Client{
		BaseURL: baseURL,
		apiKey:  supabaseKey,
		HTTPClient: &http.Client{
			Timeout: time.Minute,
		},
	}
	return client
}

type SignUpRequest struct {
	Email    string
	Password string
	MetaData map[string]any
	UsePKCE  bool
}

// SignUp registers the user's email and password to the database.
func (c *Client) SignUp(ctx context.Context, opts SignUpRequest) (*Authenticated, error) {
	body := struct {
		Email               string         `json:"email"`
		Password            string         `json:"password"`
		MetaData            map[string]any `json:"data"`
		CodeChallengeMethod string         `json:"code_challenge_method"`
		CodeChallenge       string         `json:"code_challenge"`
	}{
		Email:    opts.Email,
		Password: opts.Password,
		MetaData: opts.MetaData,
	}

	res := Authenticated{}

	if opts.UsePKCE {
		p, err := generatePKCEParams()
		if err != nil {
			return nil, err
		}
		body.CodeChallengeMethod = p.ChallengeMethod
		body.CodeChallenge = p.Challenge
		res.CodeVerifier = p.Verifier
	}

	reqBody, _ := json.Marshal(body)
	reqURL := fmt.Sprintf("%s/%s/signup", c.BaseURL, AuthEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("content-type", "application/json")
	if err := c.sendRequest(req, &res); err != nil {
		return nil, err
	}

	return &res, err
}

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignIn enters the user credentials and returns the current user if succeeded.
func (c *Client) SignIn(ctx context.Context, opts SignInRequest) (*Authenticated, error) {
	reqBody, _ := json.Marshal(opts)
	reqURL := fmt.Sprintf("%s/%s/token?grant_type=password", c.BaseURL, AuthEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("content-type", "application/json")
	res := Authenticated{}
	errRes := authenticationError{}
	hasCustomError, err := c.sendCustomRequest(req, &res, &errRes)
	if err != nil {
		return nil, err
	} else if hasCustomError {
		return nil, fmt.Errorf("%s: %s", errRes.Error, errRes.ErrorDescription)
	}

	return &res, err
}

// RefreshUser enters the user credentials and returns the current user if succeeded.
func (c *Client) RefreshUser(ctx context.Context, userToken string, refreshToken string) (*Authenticated, error) {
	reqBody, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	reqURL := fmt.Sprintf("%s/%s/token?grant_type=refresh_token", c.BaseURL, AuthEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	injectAuthorizationHeader(req, userToken)
	req.Header.Set("content-type", "application/json")
	res := Authenticated{}
	errRes := authenticationError{}
	hasCustomError, err := c.sendCustomRequest(req, &res, &errRes)
	if err != nil {
		return nil, err
	} else if hasCustomError {
		return nil, fmt.Errorf("%s: %s", errRes.Error, errRes.ErrorDescription)
	}

	return &res, err
}

type ExchangeCodeRequest struct {
	AuthCode     string `json:"auth_code"`
	CodeVerifier string `json:"code_verifier"`
}

// ExchangeCode takes an auth code and PCKE verifier and returns the current user if succeeded.
func (c *Client) ExchangeCode(ctx context.Context, opts ExchangeCodeRequest) (*Authenticated, error) {
	reqBody, _ := json.Marshal(opts)
	reqURL := fmt.Sprintf("%s/%s/token?grant_type=pkce", c.BaseURL, AuthEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("content-type", "application/json")
	res := Authenticated{}
	errRes := exchangeError{}
	hasCustomError, err := c.sendCustomRequest(req, &res, &errRes)
	if err != nil {
		return nil, err
	} else if hasCustomError {
		return nil, fmt.Errorf("%s", errRes.Message)
	}

	return &res, err
}

// SendMagicLink sends a link to a specific e-mail address for passwordless auth.
func (c *Client) SendMagicLink(ctx context.Context, email string) error {
	reqBody, _ := json.Marshal(map[string]string{"email": email})
	reqURL := fmt.Sprintf("%s/%s/magiclink", c.BaseURL, AuthEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	errRes := authError{}
	hasCustomError, err := c.sendCustomRequest(req, nil, &errRes)
	if err != nil {
		return err
	} else if hasCustomError {
		return errors.New(errRes.Message)
	}

	return err
}

type ProviderSignInRequest struct {
	Provider   string
	RedirectTo string
	Scopes     []string
	UsePKCE    bool
}

type Provider struct {
	URL          string `json:"url"`
	Provider     string `json:"provider"`
	CodeVerifier string `json:"code_verifier"`
}

// SignInWithProvider returns a URL for signing in via OAuth
func (c *Client) SignInWithProvider(opts ProviderSignInRequest) (*Provider, error) {
	if opts.Provider == "" {
		return nil, errors.New("missing required 'provider' value")
	}

	params := make(url.Values)
	params.Set("provider", opts.Provider)
	params.Set("redirect_to", opts.RedirectTo)
	params.Set("scopes", strings.Join(opts.Scopes, " "))

	details := Provider{
		URL:      fmt.Sprintf("%s/%s/authorize?%s", c.BaseURL, AuthEndpoint, params.Encode()),
		Provider: opts.Provider,
	}

	if opts.UsePKCE {
		p, err := generatePKCEParams()
		if err != nil {
			return nil, err
		}

		params.Add("code_challenge", p.Challenge)
		params.Add("code_challenge_method", p.ChallengeMethod)

		details.CodeVerifier = p.Verifier
	}

	return &details, nil
}

// User retrieves the user information based on the given token
func (c *Client) User(ctx context.Context, userToken string) (*User, error) {
	reqURL := fmt.Sprintf("%s/%s/user", c.BaseURL, AuthEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	injectAuthorizationHeader(req, userToken)
	req.Header.Set("content-type", "application/json")

	res := User{}
	errRes := authError{}
	hasCustomError, err := c.sendCustomRequest(req, &res, &errRes)
	if err != nil {
		return nil, err
	} else if hasCustomError {
		return nil, fmt.Errorf("%s", errRes.Message)
	}

	return &res, err
}

// UpdateUser updates the user information
func (c *Client) UpdateUser(ctx context.Context, userToken string, updateData map[string]interface{}) (*User, error) {
	reqBody, _ := json.Marshal(updateData)
	reqURL := fmt.Sprintf("%s/%s/user", c.BaseURL, AuthEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	injectAuthorizationHeader(req, userToken)
	req.Header.Set("content-type", "application/json")

	res := User{}
	errRes := authError{}
	hasCustomError, err := c.sendCustomRequest(req, &res, &errRes)
	if err != nil {
		return nil, err
	} else if hasCustomError {
		return nil, fmt.Errorf("%s", errRes.Message)
	}

	return &res, err
}

// ResetPasswordForEmail sends a password recovery link to the given e-mail address.
func (c *Client) ResetPasswordForEmail(ctx context.Context, email string) error {
	reqBody, _ := json.Marshal(map[string]string{"email": email})
	reqURL := fmt.Sprintf("%s/%s/recover", c.BaseURL, AuthEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	if err = c.sendRequest(req, nil); err != nil {
		return err
	}

	return err
}

// SignOut revokes the users token and session.
func (c *Client) SignOut(ctx context.Context, userToken string) error {
	reqURL := fmt.Sprintf("%s/%s/logout", c.BaseURL, AuthEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return err
	}

	injectAuthorizationHeader(req, userToken)
	req.Header.Set("content-type", "application/json")
	if err = c.sendRequest(req, nil); err != nil {
		return err
	}

	return err
}

// InviteUserByEmail sends an invite link to the given email. Returns a user.
func (c *Client) InviteUserByEmail(ctx context.Context, email string) (*User, error) {
	reqBody, _ := json.Marshal(map[string]string{"email": email})
	reqURL := fmt.Sprintf("%s/%s/invite", c.BaseURL, AuthEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	injectAuthorizationHeader(req, c.apiKey)
	req.Header.Set("content-type", "application/json")
	res := User{}
	if err := c.sendRequest(req, &res); err != nil {
		return nil, err
	}

	return &res, err
}

type PKCEParams struct {
	Challenge       string
	ChallengeMethod string
	Verifier        string
}

func generatePKCEParams() (*PKCEParams, error) {
	data := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return nil, err
	}

	// RawURLEncoding since "code challenge can only contain alphanumeric characters, hyphens, periods, underscores and tildes"
	verifier := base64.RawURLEncoding.EncodeToString(data)
	sha := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sha[:])

	pkce := &PKCEParams{
		Challenge:       challenge,
		ChallengeMethod: "S256",
		Verifier:        verifier,
	}

	return pkce, nil
}
