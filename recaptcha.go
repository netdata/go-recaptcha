package recaptcha

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const recaptchaAPIURL = "https://www.google.com/recaptcha/api/siteverify"

// Client for the reCaptcha v3 API.
type Client struct {
	SecretKey string
}

// NewClient returns a new recaptcha client.
func NewClient(secretKey string) *Client {
	return &Client{SecretKey: secretKey}
}

// APIResponse models the response of the reCaptcha v3 API.
type APIResponse struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

func (r APIResponse) Error() string {
	return fmt.Sprintf("%s\n", strings.Join(r.ErrorCodes, ", "))
}

// Score assigns a score to the response token. A score close to 1.0 designates
// a human, a score close to 0 designates a bot.
func (c *Client) Score(token string, remoteIP string) (*APIResponse, error) {
	resp, err := http.PostForm(
		recaptchaAPIURL,
		url.Values{"secret": {c.SecretKey}, "remoteip": {remoteIP}, "response": {token}})
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

	var r APIResponse
	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}
