package sand

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

const (
	iso8601 = "2006-01-02T15:04:05.00-07:00"
)

var notAllowedResponse = map[string]interface{}{
	"allowed": false,
}

//Service can be used to verify a token with SAND
type Service struct {
	Client

	//Resource is the name of this service that is registered with SAND.
	Resource string
	//The URL of the token verification endpoint, e.g., "https://oauth.example.com/warden/token/allowed"
	TokenVerifyURL string

	//The default expiry time for cache for invalid tokens and also valid tokens without expiry times
	//Default value is 3600 (1 hour)
	//Only services need this because client tokens will always give expiry time
	DefaultExpTime int

	//The scopes required to access the token verification endpoint
	Scopes []string
}

//NewService returns a Service struct.
func NewService(id, secret, tokenURL, resource, verifyURL string, scopes []string) (service *Service, err error) {
	client, err := NewClient(id, secret, tokenURL)
	if err != nil || resource == "" || verifyURL == "" {
		err = errors.New("NewService: missing required argument(s)")
		return
	}
	client.cacheType = "tokens"
	service = &Service{
		Client:         *client,
		Resource:       resource,
		TokenVerifyURL: verifyURL,
		Scopes:         scopes,
		DefaultExpTime: 3600,
	}
	return
}

//CheckRequest checks the bearer token of an incoming HTTP request and return response with 'allowed' true/false field.
//If the error is of type sand.ConnectionError, the service should respond with
//HTTP status code 502. Otherwise the client would perform unnecessary retries.
//Example with Gin:
//  func(c *gin.Context) {
//    response, err := sandService.CheckRequest(c.Request, []string{"scope1", "scope2"}, "action")
//    if err != nil || response["allowed"] != true {
//      c.JSON(sandService.ErrorCode(err), err)    //This would set 502 on ConnectionError
//    }
//  }
func (s *Service) CheckRequest(r *http.Request, targetScopes []string, action string) (map[string]interface{}, error) {
	return s.CheckRequestWithCustomRetry(r, targetScopes, action, s.MaxRetry)
}

//CheckRequestWithCustomRetry allows specifying a positive number as number of retries to
//use instead of the default MaxRetry on a per-request basis.
//Using a negative number for numRetry is equivalent to the "Request" function
func (s *Service) CheckRequestWithCustomRetry(r *http.Request, targetScopes []string, action string, numRetry int) (map[string]interface{}, error) {
	token := ExtractToken(r.Header.Get("Authorization"))
	rv, err := s.isTokenAllowed(token, targetScopes, action, numRetry)
	if err != nil {
		logger.Errorf("auth error: %v", err)
		err = AuthenticationError{"Service failed to verify the token"}
	}
	return rv, err
}

//ErrorCode gets the HTTP error code based on the error type. By default it is
//401 unauthorized; if the error is connection error, then it returns 502
func (s *Service) ErrorCode(err error) int {
	if err != nil {
		//Return 502 on error
		return http.StatusBadGateway
	}
	return http.StatusUnauthorized
}

//isTokenAllowed is the given token allowed to access this service?
func (s *Service) isTokenAllowed(token string, targetScopes []string, action string, numRetry int) (map[string]interface{}, error) {
	if token == "" {
		return notAllowedResponse, nil
	}
	if s.Cache != nil {
		//Read from cache
		result := s.Cache.Read(s.cacheKey(token, targetScopes))
		response, ok := result.(map[string]interface{})
		if ok {
			return response, nil
		}
	}
	resp, err := s.verifyToken(token, targetScopes, action, numRetry)
	if err != nil || resp == nil {
		return notAllowedResponse, err
	}
	if s.Cache != nil {
		//Write to cache
		if resp["allowed"] == true {
			exp := s.DefaultExpTime
			if resp["exp"] != nil {
				expTime, ok := resp["exp"].(string)
				if ok {
					exp = s.expiryTime(expTime)
				}
			}
			s.Cache.Write(s.cacheKey(token, targetScopes), resp, time.Duration(exp)*time.Second)
		} else {
			s.Cache.Write(s.cacheKey(token, targetScopes), notAllowedResponse, time.Duration(s.DefaultExpTime)*time.Second)
		}
	}
	return resp, nil
}

//verifyToken verifies with SAND to see if the token is allowed to access this service.
func (s *Service) verifyToken(token string, targetScopes []string, action string, numRetry int) (map[string]interface{}, error) {
	if token == "" {
		return nil, nil
	}
	accessToken, err := s.Token("service-access-token", s.Scopes, numRetry)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.SkipTLSVerify},
	}}
	data := map[string]interface{}{
		"scopes":   targetScopes,
		"token":    token,
		"resource": s.Resource,
		"action":   action,
		"context":  map[string]interface{}{},
	}
	dBytes, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", s.TokenVerifyURL, bytes.NewBuffer(dBytes))
	req.Header.Add("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, AuthenticationError{"Error response from the authentication service: " + strconv.Itoa(resp.StatusCode)}
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	return result, err
}

//expiryTime computes the expiry time given the expiry time as a string
//Example time returned by SAND: {"exp":"2016-09-06T08:32:59.71-07:00"}
func (s *Service) expiryTime(expTime string) int {
	if expTime == "" {
		return s.DefaultExpTime
	}
	t, err := time.Parse(iso8601, expTime)
	if err != nil {
		return s.DefaultExpTime
	}
	diff := t.Unix() - time.Now().Unix()
	if diff > 0 {
		return int(diff)
	}
	return s.DefaultExpTime
}
