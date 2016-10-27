package sand

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/Sirupsen/logrus"
)

const (
	iso8601 = "2006-01-02T15:04:05.00-07:00"
)

var (
	//Logger is used to log detail errors
	Logger = logrus.New()
)

//Service can be used to verify a token with SAND
type Service struct {
	Client

	//Resource is the name of this service that is registered with SAND.
	Resource string
	//The URL of the token verification endpoint, e.g., "https://oauth.example.com/warden/token/allowed"
	TokenVerifyURL string

	//The OAuth scope that are allowed to access this service.
	//Default value is empty/no scope
	TargetScopes []string

	//The default expiry time for cache for invalid tokens and also valid tokens without expiry times
	//Default value is 3600 (1 hour)
	//Only services need this because client tokens will always give expiry time
	DefaultExpTime int
}

//NewService returns a Service struct.
func NewService(id, secret, tokenURL, resource, verifyURL string) (service *Service, err error) {
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
		TargetScopes:   []string{},
		DefaultExpTime: 3600,
	}
	return
}

//CheckRequest checks the bearer token of an incoming HTTP request.
func (s *Service) CheckRequest(r *http.Request, action string) (bool, error) {
	token := ExtractToken(r.Header.Get("Authorization"))
	rv, err := s.isTokenAllowed(token, action)
	if err != nil {
		Logger.Errorf("auth error: %v", err)
		err = AuthenticationError{"Unauthorized"}
	}
	return rv, err
}

//isTokenAllowed is the given token allowed to access this service?
func (s *Service) isTokenAllowed(token, action string) (bool, error) {
	if token == "" {
		return false, errors.New("Token is empty")
	}
	if s.Cache != nil {
		//Read from cache
		result := s.Cache.Read(s.cacheKey(token))
		allowed, ok := result.(bool)
		if ok {
			return allowed, nil
		}
	}
	resp, err := s.verifyToken(token, action)
	if err != nil {
		return false, err
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
			s.Cache.Write(s.cacheKey(token), true, time.Duration(exp)*time.Second)
		} else {
			s.Cache.Write(s.cacheKey(token), false, time.Duration(s.DefaultExpTime)*time.Second)
		}
	}
	return resp["allowed"] == true, nil
}

//verifyToken verifies with SAND to see if the token is allowed to access this service.
func (s *Service) verifyToken(token, action string) (map[string]interface{}, error) {
	if token == "" {
		return nil, errors.New("Token is empty")
	}
	accessToken, err := s.Token("service-access-token")
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.SkipTLSVerify},
	}}
	data := map[string]interface{}{
		"scopes":   s.TargetScopes,
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
