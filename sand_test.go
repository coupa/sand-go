package sand

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sand", func() {
	var client *Client

	BeforeEach(func() {
		client, _ = NewClient("i", "s", "u")
		client.MaxRetry = 0
	})

	Describe("#NewClient", func() {
		It("gives error when missing required arguments", func() {
			_, err := NewClient("", "s", "u")
			Expect(err.Error()).To(Equal("NewClient: missing required argument(s)"))
		})
	})

	Describe("Token tests", func() {
		var ts *httptest.Server
		var handler func(http.ResponseWriter, *http.Request)
		BeforeEach(func() {
			ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				handler(w, r)
			}))
			client.TokenURL = ts.URL
		})
		AfterEach(func() {
			ts.Close()
		})

		Describe("#Request", func() {
			Context("with a valid token", func() {
				It("makes the request successfully", func() {
					mockResponse := &http.Response{StatusCode: 200}

					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					resp, _ := client.Request("resource", []string{"scope"}, func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					Expect(resp.StatusCode).To(Equal(200))

					mockResponse = &http.Response{StatusCode: 501}

					resp, _ = client.Request("resource", []string{"scope"}, func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					Expect(resp.StatusCode).To(Equal(501))
				})
			})

			Context("with service responding 401", func() {
				BeforeEach(func() {
					//2 retry should sleep two times: 1 + 2 = 3 seconds
					client.MaxRetry = 2
				})
				It("performs the retry", func() {
					mockResponse := &http.Response{StatusCode: 401}

					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					t1 := time.Now().Unix()
					resp, _ := client.Request("resource", []string{"scope"}, func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					t2 := time.Now().Unix()
					Expect(t2 - t1).To(BeNumerically(">=", 3))
					Expect(resp.StatusCode).To(Equal(401))
				})
			})

			Context("with service responding 502", func() {
				BeforeEach(func() {
					//3 retries should sleep 3 times: 1 + 2 + 4 = 7 seconds
					client.MaxRetry = 3
				})
				It("does not perform retry", func() {
					mockResponse := &http.Response{StatusCode: 502}

					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					t1 := time.Now().Unix()
					resp, _ := client.Request("resource", []string{"scope"}, func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					t2 := time.Now().Unix()
					Expect(t2 - t1).To(BeNumerically("<", 7))
					Expect(resp.StatusCode).To(Equal(502))
				})
			})

			Context("with calling function returning an error", func() {
				BeforeEach(func() {
					//3 retries would have taken 7 seconds
					client.MaxRetry = 3
				})
				It("returns the error without retry", func() {
					mockResponse := &http.Response{StatusCode: 200}

					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					t1 := time.Now().Unix()
					_, err := client.Request("resource", []string{"scope"}, func(token string) (*http.Response, error) {
						return mockResponse, errors.New("Test")
					})
					t2 := time.Now().Unix()
					Expect(t2 - t1).To(BeNumerically("<", 7))
					Expect(err.Error()).To(Equal("Test"))
				})
			})
		})

		Describe("#RequestWithCustomRetry", func() {
			Context("with a valid token", func() {
				It("makes the request successfully", func() {
					mockResponse := &http.Response{StatusCode: 200}

					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					resp, _ := client.RequestWithCustomRetry("resource", []string{"scope"}, 0, func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					Expect(resp.StatusCode).To(Equal(200))

					mockResponse = &http.Response{StatusCode: 501}

					resp, _ = client.RequestWithCustomRetry("resource", []string{"scope"}, 0, func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					Expect(resp.StatusCode).To(Equal(501))
				})
			})

			Context("with service responding 401", func() {
				It("performs the retry based on the numRetry param", func() {
					mockResponse := &http.Response{StatusCode: 401}

					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					t1 := time.Now().Unix()
					resp, _ := client.RequestWithCustomRetry("resource", []string{"scope"}, 1, func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					t2 := time.Now().Unix()
					Expect(t2 - t1).To(BeNumerically(">=", 1))
					Expect(resp.StatusCode).To(Equal(401))

					client.MaxRetry = 2
					t1 = time.Now().Unix()
					resp, _ = client.RequestWithCustomRetry("resource", []string{"scope"}, 0, func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					t2 = time.Now().Unix()
					Expect(t2 - t1).To(BeNumerically("<", 1))
					Expect(resp.StatusCode).To(Equal(401))

					t1 = time.Now().Unix()
					resp, _ = client.RequestWithCustomRetry("resource", []string{"scope"}, -1, func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					t2 = time.Now().Unix()
					Expect(t2 - t1).To(BeNumerically(">=", 3))
					Expect(resp.StatusCode).To(Equal(401))
				})
			})

			Context("with service responding 502", func() {
				It("does not perform retry", func() {
					mockResponse := &http.Response{StatusCode: 502}

					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					t1 := time.Now().Unix()
					resp, _ := client.RequestWithCustomRetry("resource", []string{"scope"}, 3, func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					t2 := time.Now().Unix()
					Expect(t2 - t1).To(BeNumerically("<", 7))
					Expect(resp.StatusCode).To(Equal(502))
				})
			})

			Context("with calling function returning an error", func() {
				It("returns the error without retry", func() {
					mockResponse := &http.Response{StatusCode: 200}

					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					t1 := time.Now().Unix()
					_, err := client.RequestWithCustomRetry("resource", []string{"scope"}, 3, func(token string) (*http.Response, error) {
						return mockResponse, errors.New("Test")
					})
					t2 := time.Now().Unix()
					Expect(t2 - t1).To(BeNumerically("<", 7))
					Expect(err.Error()).To(Equal("Test"))
				})
			})
		})

		Describe("#Token", func() {
			Context("with a valid response", func() {
				It("returns the token", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					token, err := client.Token("resource", []string{"scope"}, -1)
					Expect(err).To(BeNil())
					Expect(token).To(Equal("abc"))
				})
			})

			Context("with an empty response", func() {
				It("returns an invalid access token error", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					token, err := client.Token("resource", []string{"scope"}, -1)
					Expect(err).To(Equal(AuthenticationError{"Invalid access token"}))
					Expect(token).To(Equal(""))

					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					token, err = client.Token("resource", []string{"scope"}, -1)
					Expect(err).To(Equal(AuthenticationError{"Invalid access token"}))
					Expect(token).To(Equal(""))
				})
			})
		})

		Describe("#oauthToken", func() {
			Context("with a valid response", func() {
				It("returns the token", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
							"expires_in":   "3600",
							"scope":        "",
							"token_type":   "bearer",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					token, err := client.oauthToken([]string{"scope"}, -1)
					Expect(err).To(BeNil())
					Expect(token.AccessToken).To(Equal("abc"))
				})
				It("returns the token without expiry time", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{
							"access_token": "abc",
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					token, err := client.oauthToken([]string{"scope"}, -1)
					Expect(err).To(BeNil())
					Expect(token.AccessToken).To(Equal("abc"))
				})
			})

			Context("with an empty response", func() {
				It("returns an empty oauth token", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					token, err := client.oauthToken([]string{"scope"}, -1)
					Expect(err).To(BeNil())
					Expect(token.AccessToken).To(Equal(""))
				})
			})

			Context("with an error response", func() {
				BeforeEach(func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusNotFound)
					}
				})
				It("returns an error", func() {
					token, err := client.oauthToken([]string{"scope"}, -1)
					_, yes := err.(AuthenticationError)
					Expect(yes).To(BeTrue())
					Expect(token).To(BeNil())
				})

				Context("and retry twice", func() {
					It("should take at least 3 seconds to finish the retry and return error", func() {
						client.MaxRetry = 2
						t1 := time.Now().Unix()
						//Retry should sleep two times: 1 + 2 = 3 seconds
						token, err := client.oauthToken([]string{"scope"}, -1)
						t2 := time.Now().Unix()
						Expect(t2 - t1).To(BeNumerically(">=", 3))
						_, yes := err.(AuthenticationError)
						Expect(yes).To(BeTrue())
						Expect(token).To(BeNil())
					})
				})
			})
			Context("with connection error", func() {
				It("returns a sand.AuthenticationError", func() {
					client.TokenURL = ""
					token, err := client.oauthToken([]string{"scope"}, -1)
					Expect(token).To(BeNil())
					_, yes := err.(AuthenticationError)
					Expect(yes).To(BeTrue())
				})
			})
		})
	})

	Describe("#cacheKey", func() {
		It("returns the cache key", func() {
			Expect(client.cacheKey("hello", nil, "")).To(Equal(client.CacheRoot + "/" + client.cacheType + "/hello"))
			Expect(client.cacheKey("hello", []string{}, "")).To(Equal(client.CacheRoot + "/" + client.cacheType + "/hello"))
			Expect(client.cacheKey("", nil, "")).To(Equal(client.CacheRoot + "/" + client.cacheType + "/"))

			Expect(client.cacheKey("hello", []string{"a", "b"}, "")).To(Equal(client.CacheRoot + "/" + client.cacheType + "/hello/a_b"))
			Expect(client.cacheKey("", []string{"a"}, "")).To(Equal(client.CacheRoot + "/" + client.cacheType + "//a"))
		})
	})
})
