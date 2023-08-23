package supabase

import "time"

type Authenticated struct {
	AccessToken          string `json:"access_token"`
	TokenType            string `json:"token_type"`
	ExpiresIn            int    `json:"expires_in"`
	RefreshToken         string `json:"refresh_token"`
	User                 User   `json:"user"`
	ProviderToken        string `json:"provider_token"`
	ProviderRefreshToken string `json:"provider_refresh_token"`
}

type User struct {
	ID                 string                    `json:"id"`
	Aud                string                    `json:"aud"`
	Role               string                    `json:"role"`
	Email              string                    `json:"email"`
	ConfirmationSentAt time.Time                 `json:"confirmation_sent_at"`
	ConfirmedAt        time.Time                 `json:"confirmed_at"`
	InvitedAt          time.Time                 `json:"invited_at"`
	AppMetadata        struct{ provider string } `json:"app_metadata"`
	UserMetadata       map[string]interface{}    `json:"user_metadata"`
	LastSignInAt       time.Time                 `json:"last_sign_in_at"`
	CreatedAt          time.Time                 `json:"created_at"`
	UpdatedAt          time.Time                 `json:"updated_at"`
}

type authenticationError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type authError struct {
	Message string `json:"message"`
}

type exchangeError struct {
	Message string `json:"msg"`
}
