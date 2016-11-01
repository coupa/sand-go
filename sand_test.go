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
					resp, _ := client.Request("resource", func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					Expect(resp.StatusCode).To(Equal(200))

					mockResponse = &http.Response{StatusCode: 501}

					resp, _ = client.Request("resource", func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					Expect(resp.StatusCode).To(Equal(501))
				})
			})
			Context("with service responding 401", func() {
				BeforeEach(func() {
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
					//Retry should sleep two times: 1 + 2 = 3 seconds
					resp, _ := client.Request("resource", func(token string) (*http.Response, error) {
						return mockResponse, nil
					})
					t2 := time.Now().Unix()
					Expect(t2 - t1).To(BeNumerically(">=", 3))
					Expect(resp.StatusCode).To(Equal(401))
				})
			})
			Context("with calling function has an error", func() {
				BeforeEach(func() {
					client.MaxRetry = 2
				})
				It("returns the error", func() {
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
					_, err := client.Request("resource", func(token string) (*http.Response, error) {
						return mockResponse, errors.New("Test")
					})
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
					token, err := client.Token("resource")
					Expect(err).To(BeNil())
					Expect(token).To(Equal("abc"))
				})
			})

			Context("with an empty response", func() {
				It("returns an access token empty error", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						resp := map[string]interface{}{}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					token, err := client.Token("resource")
					Expect(err.Error()).To(Equal("Received a blank access token"))
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
					token, err = client.Token("resource")
					Expect(err.Error()).To(Equal("Received a blank access token"))
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
					token, err := client.oauthToken()
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
					token, err := client.oauthToken()
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
					token, err := client.oauthToken()
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
					token, err := client.oauthToken()
					Expect(err).NotTo(BeNil())
					Expect(token).To(BeNil())
				})

				Context("and retry twice", func() {
					It("should take at least 3 seconds to finish the retry and return error", func() {
						client.MaxRetry = 2
						t1 := time.Now().Unix()
						//Retry should sleep two times: 1 + 2 = 3 seconds
						token, err := client.oauthToken()
						t2 := time.Now().Unix()
						Expect(err).NotTo(BeNil())
						Expect(token).To(BeNil())
						Expect(t2 - t1).To(BeNumerically(">=", 3))
					})
				})
			})
		})
	})

	Describe("#cacheKey", func() {
		It("returns the cache key", func() {
			Expect(client.cacheKey("hello")).To(Equal(client.CacheRoot + "/" + client.cacheType + "/hello"))
			Expect(client.cacheKey("")).To(Equal(client.CacheRoot + "/" + client.cacheType + "/"))
		})
	})
})
