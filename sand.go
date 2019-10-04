package sand

import (
	"crypto/tls"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/coupa/sand-go/cache"
	log "github.com/sirupsen/logrus"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	defaultExpiryTime = 3595 * time.Second
)

//Client can be used to request token from an OAuth2 server
type Client struct {
	//The client ID of the OAuth2 client credentials
	ClientID string
	//The client secret of the OAuth2 client credentials
	ClientSecret string
	//TokenURL: The token endpoint of the OAuth2 server, e.g., "https://oauth.example.com/oauth2/token"
	TokenURL string

	//SkipTLSVerify skips checking the SSL certificate. Should be false for production.
	//Default is false
	SkipTLSVerify bool

	//DefaultRetryCount is the default number of retries to perform with exponential backoff when
	//1. Clients receive 401 response from services
	//2. Clients' or services' connections to the OAuth2 server fails.
	//Default value is 5
	DefaultRetryCount int
	Cache             cache.Cache

	//CacheRoot is the root of the cache key for storing tokens in the cache.
	//The overall cache key will look like: <CacheRoot>/<cacheType>/<some key>
	//Default value is "sand"
	CacheRoot string

	//Default value is "resources" for sand.Client
	//Default value is "tokens" for sand.Service
	cacheType string
}

//NewClient returns a Client with default option values. The default expiration
//time is set to 3595 seconds.
//If you don't want to use a cache for some very convincing reason, you can set
//client's Cache to nil.
func NewClient(id, secret, tokenURL string) (client *Client, err error) {
	return NewClientWithExpiration(id, secret, tokenURL, defaultExpiryTime)
}

//NewClientWithExpiration returns a Client with default option values with specified
//expiration time on the cache.
//If you don't want to use a cache for some very convincing reason, you can set
//client's Cache to nil.
func NewClientWithExpiration(id, secret, tokenURL string, cacheExpiration time.Duration) (client *Client, err error) {
	if id == "" || secret == "" || tokenURL == "" {
		err = errors.New("NewClient: missing required argument(s)")
		return
	}
	client = &Client{
		ClientID:          id,
		ClientSecret:      secret,
		TokenURL:          tokenURL,
		SkipTLSVerify:     false,
		DefaultRetryCount: 5,
		Cache:             cache.NewGoCache(cacheExpiration, cacheExpiration),
		CacheRoot:         "sand",
		cacheType:         "resources",
	}
	return
}

//Request makes a service API request by first obtaining the access token from
//SAND. Then it deligates the token to the underlying function to make the service
//call. If the service returns 401, it performs exponential retry by requesting
//new tokens from SAND and make the service call. If the service returns 502, the
//service failed to connect to the authentication service and no retry will occur.
//Usage Example:
// client.Request("some-service", []string{"s1", "s2"}, func(token string) (*http.Response, error) {
//   // Make http request with "Bearer {token}" in the Authorization header
//   // return the response and error
// })
func (c *Client) Request(cacheKey string, scopes []string, exec func(string) (*http.Response, error)) (*http.Response, error) {
	return c.RequestWithCustomRetry(cacheKey, scopes, c.DefaultRetryCount, exec)
}

//RequestWithCustomRetry allows specifying numRetry as the number of retries to
//use instead of the DefaultRetryCount, on a per-request basis. numRetry MUST be
//at least one so that if a client's token has expired, it can get a new token when
//retrying, at least once.
//Using a negative number for numRetry is equivalent to the "Request" function,
//which uses DefaultRetryCount.
//The retry durations are: 1, 2, 4, 8, 16,... seconds
func (c *Client) RequestWithCustomRetry(cacheKey string, scopes []string, numRetry int, exec func(string) (*http.Response, error)) (*http.Response, error) {
	clientRetry := c.clientRequestRetryCount(numRetry)

	token, err := c.Token(cacheKey, scopes, numRetry)
	if err != nil {
		return nil, err
	}
	resp, err := exec(token)
	if err != nil {
		return resp, err
	}
	if clientRetry > 0 {
		//Retry only on 401 response from the service.
		//Get a fresh token from authentication service and retry.
		for retry := 0; resp.StatusCode == http.StatusUnauthorized && retry < clientRetry; retry++ {
			sleep := time.Duration(math.Pow(2, float64(retry)))
			log.Warnf("Sand request: retrying after %d sec on %d", sleep, http.StatusUnauthorized)
			time.Sleep(sleep * time.Second)
			//Prevent reading from cache on retry
			if c.Cache != nil {
				c.Cache.Delete(c.cacheKey(cacheKey, scopes, ""))
			}
			//Set number of retry to 0, since we are already retrying here, don't retry
			//when getting the token. Otherwise it may lock up for a long time
			token, err = c.Token(cacheKey, scopes, 0)
			if err != nil {
				return resp, err
			}
			resp, err = exec(token)
			if err != nil {
				return resp, err
			}
		}
	}
	return resp, err
}

//Token returns an OAuth2 token string retrieved from the OAuth2 server. It also puts the
//token in the cache up to specified amount of time.
func (c *Client) Token(cacheKey string, scopes []string, numRetry int) (string, error) {
	token, err := c.OAuth2Token(cacheKey, scopes, numRetry)
	if err == nil {
		return token.AccessToken, err
	}
	return "", err
}

//OAuth2Token returns an OAuth2 token retrieved from the OAuth2 server. It also puts the
//token in the cache up to specified amount of time.
func (c *Client) OAuth2Token(cacheKey string, scopes []string, numRetry int) (*oauth2.Token, error) {
	var ckey string
	if c.Cache != nil && cacheKey != "" {
		ckey = c.cacheKey(cacheKey, scopes, "")
		value := c.Cache.Read(ckey)
		if value != nil {
			if tk, ok := value.(oauth2.Token); ok {
				return &tk, nil
			}
		}
	}
	token, err := c.OAuth2TokenWithoutCaching(scopes, numRetry)
	if err != nil {
		return nil, err
	}
	if c.Cache != nil && cacheKey != "" {
		expiresIn := 0
		//If token.Expiry is zero, it means no limit. Otherwise we compute the limit.
		if !token.Expiry.IsZero() {
			expiresIn = int(token.Expiry.Unix() - time.Now().Unix())
		}
		if expiresIn >= 0 {
			c.Cache.Write(ckey, *token, time.Duration(expiresIn)*time.Second)
		}
	}
	return token, nil
}

//OAuth2TokenWithoutCaching makes the connection to the OAuth server and returns oauth2.Token
//The returned token could have empty accessToken.
func (c *Client) OAuth2TokenWithoutCaching(scopes []string, numRetry int) (token *oauth2.Token, err error) {
	numRetry = c.tokenRequestRetryCount(numRetry)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.SkipTLSVerify},
	}}
	ctx := context.TODO()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	config := clientcredentials.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		TokenURL:     c.TokenURL,
		Scopes:       scopes,
	}
	token, err = config.Token(ctx)
	if err != nil && numRetry > 0 {
		for retry := 0; err != nil && retry < numRetry; retry++ {
			//Exponential backoff on the retry
			sleep := time.Duration(math.Pow(2, float64(retry)))
			log.Warnf("Sand token: retrying after %d sec because of error: %v", sleep, err)
			time.Sleep(sleep * time.Second)
			token, err = config.Token(ctx)
		}
	}
	if err != nil {
		err = AuthenticationError{err.Error()}
	}
	return token, err
}

//cacheKey builds the cache key in the format: <CachRoot>/<cacheType>/<key>
func (c *Client) cacheKey(key string, scopes []string, resource string) string {
	rv := c.CacheRoot + "/" + c.cacheType + "/" + key
	if len(scopes) > 0 {
		rv += "/" + strings.Join(scopes, "_")
	}
	if resource != "" {
		rv += "/" + resource
	}
	return rv
}

//For client requests to services, the retry must be at least 1 in case that the
//token is expired, then a retry would make the client get a new token.
func (c *Client) clientRequestRetryCount(count int) int {
	if count >= 1 {
		return count
	}
	if count == 0 || c.DefaultRetryCount < 1 {
		return 1
	}
	return c.DefaultRetryCount
}

//For requests to get Sand access tokens, we allow 0 retry if the caller doesn't
//want to retry. Specifying a negative number will make it use the default retry count.
func (c *Client) tokenRequestRetryCount(count int) int {
	if count >= 0 {
		return count
	}
	if c.DefaultRetryCount < 0 {
		return 0
	}
	return c.DefaultRetryCount
}
