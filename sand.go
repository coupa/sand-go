package sand

import (
	"crypto/tls"
	"errors"
	"math"
	"net/http"
	"time"

	"github.com/coupa/sand-go/cache"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

//Client can be used to request token from an OAuth2 server
type Client struct {
	//The client ID of the OAuth2 client credentials
	ClientID string
	//The client secret of the OAuth2 client credentials
	ClientSecret string
	//TokenURL: The token endpoint of the OAuth2 server, e.g., "https://oauth.example.com/oauth2/token"
	TokenURL string

	//Scopes is an array of scopes that is the OAuth scope of this client.
	//Default value is empty/no scope
	Scopes []string

	//SkipTLSVerify skips checking the SSL certificate. Should be false for production.
	//Default is false
	SkipTLSVerify bool

	//MaxRetry is the maximum number of retries to perform with exponential backoff
	//when connecting to the OAuth2 server fails.
	//Default value is 5
	MaxRetry int
	Cache    cache.Cache

	//CacheRoot is the root of the cache key for storing tokens in the cache.
	//The overall cache key will look like: <CacheRoot>/<cacheType>/<some key>
	//Default value is "sand"
	CacheRoot string

	//Default value is "resources" for sand.Client
	//Default value is "tokens" for sand.Service
	cacheType string
}

//NewClient returns a Client with default option values.
func NewClient(id, secret, tokenURL string) (client *Client, err error) {
	if id == "" || secret == "" || tokenURL == "" {
		err = errors.New("NewClient: missing required argument(s)")
		return
	}
	client = &Client{
		ClientID:      id,
		ClientSecret:  secret,
		TokenURL:      tokenURL,
		Scopes:        []string{},
		SkipTLSVerify: false,
		MaxRetry:      5,
		Cache:         nil,
		CacheRoot:     "sand",
		cacheType:     "resources",
	}
	return
}

//Request makes a service API request by first obtaining the access token from
//SAND. Then it deligates the token to the underlying function to make the service
//call. If the service returns 401, it performs exponential retry by requesting
//new tokens from SAND and make the service call.
func (c *Client) Request(resourceKey string, exec func(string) (*http.Response, error)) (*http.Response, error) {
	token, err := c.Token(resourceKey)
	if err != nil {
		return nil, err
	}
	resp, err := exec(token)
	if err != nil {
		return resp, err
	}
	if c.MaxRetry > 0 {
		for numRetry := 0; resp.StatusCode == 401 && numRetry < c.MaxRetry; numRetry++ {
			sleep := time.Duration(math.Pow(2, float64(numRetry)))
			time.Sleep(sleep * time.Second)
			//Prevent reading from cache on retry
			if c.Cache != nil {
				c.Cache.Delete(c.cacheKey(resourceKey))
			}
			resp, err = exec(token)
			if err != nil {
				return resp, err
			}
		}
	}
	if resp.StatusCode == 401 {
		err = errors.New("Failed to access service with token")
	}
	return resp, err
}

//Token returns an OAuth token retrieved from the OAuth2 server. It also puts the
//token in the cache up to specified amount of time.
func (c *Client) Token(resourceKey string) (string, error) {
	if c.Cache != nil {
		if resourceKey == "" {
			return "", errors.New("resource key cannot be blank when cache is present")
		}
		token := c.Cache.Read(c.cacheKey(resourceKey))
		if token != nil {
			return token.(string), nil
		}
	}
	token, err := c.oauthToken()
	if err != nil {
		return "", err
	}
	if token.AccessToken == "" {
		return "", errors.New("Received a blank access token")
	}
	if c.Cache != nil {
		expiresIn := 0
		//If token.Expiry is zero, it means no limit. Otherwise we compute the limit.
		if !token.Expiry.IsZero() {
			expiresIn = int(token.Expiry.Unix() - time.Now().Unix())
		}
		if expiresIn >= 0 {
			c.Cache.Write(c.cacheKey(resourceKey), token.AccessToken, time.Duration(expiresIn)*time.Second)
		}
	}
	return token.AccessToken, nil
}

//oauthToken makes the connection to the OAuth server and returns oauth2.Token
//The returned token could have empty accessToken.
func (c *Client) oauthToken() (token *oauth2.Token, err error) {
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.SkipTLSVerify},
	}}
	ctx := context.TODO()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	config := clientcredentials.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		TokenURL:     c.TokenURL,
		Scopes:       c.Scopes,
	}
	token, err = config.Token(ctx)
	if err != nil && c.MaxRetry > 0 {
		for numRetry := 0; err != nil && numRetry < c.MaxRetry; numRetry++ {
			//Exponential backoff on the retry
			sleep := time.Duration(math.Pow(2, float64(numRetry)))
			time.Sleep(sleep * time.Second)
			token, err = config.Token(ctx)
		}
	}
	return token, err
}

//cacheKey builds the cache key in the format: <CachRoot>/<cacheType>/<key>
func (c *Client) cacheKey(key string) string {
	return c.CacheRoot + "/" + c.cacheType + "/" + key
}
