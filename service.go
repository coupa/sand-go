package sand

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
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

	//The default resource name that this Service will check the token against.
	Resource string

	//Default context
	Context map[string]interface{}

	//The URL of the token verification endpoint, e.g., "https://oauth.example.com/warden/token/allowed"
	TokenVerifyURL string

	//The default expiry time for cache for invalid tokens and also valid tokens without expiry times
	//Default value is 3600 (1 hour)
	//Only services need this because client tokens will always give expiry time
	DefaultExpTime int

	//The scopes required for the service to access the token verification endpoint
	Scopes []string
}

type VerificationOption struct {
	TargetScopes []string
	Resource     string
	Action       string
	Context      map[string]interface{}
	NumRetry     *int
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
		Context:        map[string]interface{}{},
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
	return s.CheckRequestWithCustomRetry(r, targetScopes, action, s.DefaultRetryCount)
}

//CheckRequestWithCustomRetry allows specifying a positive number as number of retries to
//use instead of using DefaultRetryCount on a per-request basis.
//Using a negative number for numRetry is equivalent to the "Request" function
func (s *Service) CheckRequestWithCustomRetry(r *http.Request, targetScopes []string, action string, numRetry int) (map[string]interface{}, error) {
	return s.VerifyRequest(r, VerificationOption{TargetScopes: targetScopes, Action: action, NumRetry: &numRetry})
}

//VerifyRequest
//Remember to set a reasonable NumRetry value (>= 0) for the VerificationOption
func (s *Service) VerifyRequest(r *http.Request, opt VerificationOption) (map[string]interface{}, error) {
	token := ExtractToken(r.Header.Get("Authorization"))
	rv, err := s.VerifyTokenWithCache(token, opt)
	if err != nil {
		log.Error(err)
		err = AuthenticationError{"Service failed to verify the token: " + err.Error()}
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

//VerifyTokenWithCache tries to get the result for this token from the cache first.
//If not found in cache, if will make a token verification request with Sand.
func (s *Service) VerifyTokenWithCache(token string, opt VerificationOption) (map[string]interface{}, error) {
	s.buildOption(&opt)
	if token == "" || opt.Resource == "" {
		return notAllowedResponse, nil
	}

	var ckey string
	if s.Cache != nil {
		//Calculate cache key for use later
		ckey = s.cacheKey(token, opt.TargetScopes, opt.Resource)
		//Read from cache
		result := s.Cache.Read(ckey)
		response, ok := result.(map[string]interface{})
		if ok {
			return response, nil
		}
	}
	resp, err := s.verifyToken(token, opt)
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
			s.Cache.Write(ckey, resp, time.Duration(exp)*time.Second)
		} else {
			s.Cache.Write(ckey, notAllowedResponse, time.Duration(s.DefaultExpTime)*time.Second)
		}
	}
	return resp, nil
}

//Set the defaults for values that are not given.
func (s *Service) buildOption(opt *VerificationOption) {
	if opt.Resource == "" {
		opt.Resource = s.Resource
	}
	if len(opt.Context) == 0 {
		opt.Context = s.Context
	}
	if len(opt.TargetScopes) == 0 {
		opt.TargetScopes = []string{}
	}
	retry := s.DefaultRetryCount
	if opt.NumRetry != nil {
		retry = *opt.NumRetry
	}
	retry = s.tokenRequestRetryCount(retry)
	opt.NumRetry = &retry
}

//verifyToken verifies with SAND to see if the token is allowed to access this service.
func (s *Service) verifyToken(token string, opt VerificationOption) (map[string]interface{}, error) {
	if token == "" || opt.Resource == "" {
		return nil, nil
	}
	accessToken, err := s.Token("service-access-token", s.Scopes, *opt.NumRetry)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = s.SkipTLSVerify
	client := &http.Client{Transport: transport}
	data := map[string]interface{}{
		"scopes":   opt.TargetScopes,
		"token":    token,
		"resource": opt.Resource,
		"action":   opt.Action,
		"context":  opt.Context,
	}
	dBytes, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", s.TokenVerifyURL, bytes.NewBuffer(dBytes))
	req.Header.Add("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		str := fmt.Sprintf("Error response from the authentication service: %d - %s", resp.StatusCode, body)
		if resp.StatusCode == 500 {
			//When the response is 500, the token may be expired. So let the client retry
			//and return 401 by returning nil, so that the result is not cached.
			log.Error(str)
			return nil, nil
		}
		return nil, AuthenticationError{Message: str}
	}
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
