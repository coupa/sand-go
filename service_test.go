package sand

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/coupa/sand-go/cache"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	oldProxy    string
	oldProxySet bool
	ps          *httptest.Server
)

func ItBehavesLikeVerifyTokenWithCache(handler *func(http.ResponseWriter, *http.Request), subject func(string, []string, string, int) (map[string]interface{}, error)) {
	Context("with empty token", func() {
		It("returns response with allowed: false", func() {
			t, err := subject("", []string{"scope"}, "", -1)
			Expect(t).To(Equal(notAllowedResponse))
			Expect(err).To(BeNil())
		})
	})

	Context("with an error response", func() {
		It("returns a connection error", func() {
			*handler = func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}
			t, err := subject("abc", []string{"scope"}, "", -1)
			Expect(t["allowed"]).To(Equal(false))
			_, yes := err.(AuthenticationError)
			Expect(yes).To(BeTrue())
		})
	})

	Context("with allowed response", func() {
		It("returns response with allowed: true", func() {
			*handler = func(w http.ResponseWriter, r *http.Request) {
				var resp map[string]interface{}
				if r.RequestURI == "/" {
					resp = map[string]interface{}{"access_token": "def"}
				} else if r.RequestURI == "/v" {
					Expect(r.Header.Get("Authorization")).To(Equal("Bearer def"))
					resp = map[string]interface{}{"allowed": true}
				}
				exp, _ := json.Marshal(resp)
				fmt.Fprintf(w, string(exp))
			}
			t, err := subject("abc", []string{"scope"}, "", -1)
			Expect(t).To(Equal(map[string]interface{}{"allowed": true}))
			Expect(err).To(BeNil())
		})
	})

	Context("with not allowed response", func() {
		It("returns response with allowed: false", func() {
			*handler = func(w http.ResponseWriter, r *http.Request) {
				var resp map[string]interface{}
				if r.RequestURI == "/" {
					resp = map[string]interface{}{"access_token": "def"}
				} else if r.RequestURI == "/v" {
					Expect(r.Header.Get("Authorization")).To(Equal("Bearer def"))
					resp = map[string]interface{}{"allowed": false}
				}
				exp, _ := json.Marshal(resp)
				fmt.Fprintf(w, string(exp))
			}
			t, err := subject("abc", []string{"scope"}, "", -1)
			Expect(t["allowed"]).To(Equal(false))
			Expect(err).To(BeNil())
		})
	})
}

var _ = BeforeSuite(func() {
	oldProxy, oldProxySet = os.LookupEnv("HTTP_PROXY")
	ps = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	os.Setenv("HTTP_PROXY", ps.URL)
})

var _ = AfterSuite(func() {
	if oldProxySet {
		os.Setenv("HTTP_PROXY", oldProxy)
	} else {
		os.Unsetenv("HTTP_PROXY")
	}
	ps.Close()
})

var _ = Describe("Service", func() {
	var service *Service

	BeforeEach(func() {
		caches = map[time.Duration]cache.Cache{}
		service, _ = NewService("i", "s", "u", "r", "/v", []string{"scope"})
		service.DefaultRetryCount = 0
	})

	Describe("#NewService", func() {
		It("gives error when missing required arguments", func() {
			_, err := NewService("", "s", "u", "r", "/v", []string{"scope"})
			Expect(err.Error()).To(Equal("NewService: missing required argument(s)"))
			_, err = NewService("i", "s", "u", "", "/v", []string{"scope"})
			Expect(err.Error()).To(Equal("NewService: missing required argument(s)"))
		})

		It("uses the same global cache", func() {
			c1, err := NewService("c", "s", "u", "r", "/v", []string{"scope"})
			Expect(err).To(BeNil())

			c2, err := NewClient("a", "s", "u")
			Expect(err).To(BeNil())

			Expect(c2.Cache).To(Equal(caches[defaultExpiryTime]))
			Expect(c1.Cache).To(Equal(c2.Cache))
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
			service.TokenURL = ts.URL
			service.TokenVerifyURL = ts.URL + "/v"
		})
		AfterEach(func() {
			ts.Close()
		})

		Describe("#CheckRequest", func() {
			Context("with empty token", func() {
				It("returns response with allowed: false with no error", func() {
					r := http.Request{Header: http.Header{}}
					r.Header.Set("Authorization", "")
					t, err := service.CheckRequest(&r, []string{"scope"}, "")
					Expect(t["allowed"]).To(Equal(false))
					Expect(err).To(BeNil())

					r.Header.Set("Authorization", "bad bearer token")
					t, err = service.CheckRequest(&r, []string{"scope"}, "")
					Expect(t).To(Equal(notAllowedResponse))
					Expect(err).To(BeNil())
				})
			})

			Context("with service unable to retrieve an access token", func() {
				It("returns an error of type sand.AuthenticationError", func() {
					service.TokenURL = ""
					r := http.Request{Header: http.Header{}}
					r.Header.Set("Authorization", "Bearer abc")
					t, err := service.CheckRequest(&r, []string{"scope"}, "")
					Expect(t["allowed"]).To(Equal(false))
					_, yes := err.(AuthenticationError)
					Expect(yes).To(BeTrue())
				})
			})

			Context("with service unable to verify an access token", func() {
				It("returns an error of type sand.AuthenticationError", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						var resp map[string]interface{}
						if r.RequestURI == "/" {
							resp = map[string]interface{}{"access_token": "def"}
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					service.TokenVerifyURL = ""
					r := http.Request{Header: http.Header{}}
					r.Header.Set("Authorization", "Bearer abc")
					t, err := service.CheckRequest(&r, []string{"scope"}, "")
					Expect(t["allowed"]).To(Equal(false))
					_, yes := err.(AuthenticationError)
					Expect(yes).To(BeTrue())
				})
			})
		})

		Describe("#CheckRequestWithCustomRetry", func() {
			Context("with service unable to retrieve an access token", func() {
				It("performs retry and returns an error of type sand.AuthenticationError", func() {
					service.TokenURL = ""
					r := http.Request{Header: http.Header{}}
					r.Header.Set("Authorization", "Bearer abc")
					t1 := time.Now().Unix()
					t, err := service.CheckRequestWithCustomRetry(&r, []string{"scope"}, "", 2)
					t2 := time.Now().Unix()
					Expect(t2 - t1).To(BeNumerically(">=", 3))
					Expect(t["allowed"]).To(Equal(false))
					_, yes := err.(AuthenticationError)
					Expect(yes).To(BeTrue())
				})
			})
		})

		Describe("#VerifyTokenWithCache", func() {
			ItBehavesLikeVerifyTokenWithCache(&handler,
				func(token string, targetScopes []string, action string, numRetry int) (map[string]interface{}, error) {
					return service.VerifyTokenWithCache(token, VerificationOption{TargetScopes: targetScopes, Action: action})
				})

			Context("with numRetry", func() {
				ItBehavesLikeVerifyTokenWithCache(&handler,
					func(token string, targetScopes []string, action string, numRetry int) (map[string]interface{}, error) {
						return service.VerifyTokenWithCache(token, VerificationOption{TargetScopes: targetScopes, Action: action, NumRetry: &numRetry})
					})
			})

			Context("with resource", func() {
				ItBehavesLikeVerifyTokenWithCache(&handler,
					func(token string, targetScopes []string, action string, numRetry int) (map[string]interface{}, error) {
						return service.VerifyTokenWithCache(token, VerificationOption{TargetScopes: targetScopes, Action: action, Resource: "resource", NumRetry: &numRetry})
					})
			})

			Context("with context", func() {
				ItBehavesLikeVerifyTokenWithCache(&handler,
					func(token string, targetScopes []string, action string, numRetry int) (map[string]interface{}, error) {
						return service.VerifyTokenWithCache(token, VerificationOption{TargetScopes: targetScopes, Action: action, Resource: "resource", Context: map[string]interface{}{}, NumRetry: &numRetry})
					})
			})
		})

		Describe("#verifyToken", func() {
			minus_one := -1
			Context("with empty token", func() {
				It("returns nil", func() {
					t, err := service.verifyToken("", VerificationOption{TargetScopes: []string{"scope"}, Action: "", Resource: "resource", Context: nil, NumRetry: &minus_one})
					Expect(t).To(BeNil())
					Expect(err).To(BeNil())
				})
			})

			Context("with an error response", func() {
				It("returns an error", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusNotFound)
					}
					t, err := service.verifyToken("abc", VerificationOption{TargetScopes: []string{"scope"}, Action: "", Resource: "resource", Context: nil, NumRetry: &minus_one})
					Expect(t).To(BeNil())
					_, yes := err.(AuthenticationError)
					Expect(yes).To(BeTrue())
				})
			})

			Context("with a valid token and valid response", func() {
				It("returns allowed response", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						var resp map[string]interface{}
						if r.RequestURI == "/" {
							resp = map[string]interface{}{"access_token": "def"}
						} else if r.RequestURI == "/v" {
							Expect(r.Header.Get("Authorization")).To(Equal("Bearer def"))
							resp = map[string]interface{}{"allowed": true}
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					t, err := service.verifyToken("abc", VerificationOption{TargetScopes: []string{"scope"}, Action: "", Resource: "resource", Context: nil, NumRetry: &minus_one})
					Expect(err).To(BeNil())
					Expect(t).To(Equal(map[string]interface{}{"allowed": true}))
				})
			})

			Context("with 500 response when verifying a token", func() {
				It("returns nil", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						var resp map[string]interface{}
						if r.RequestURI == "/" {
							resp = map[string]interface{}{"access_token": "def"}
							exp, _ := json.Marshal(resp)
							fmt.Fprintf(w, string(exp))
						} else if r.RequestURI == "/v" {
							w.WriteHeader(http.StatusInternalServerError)
						}
					}
					t, err := service.verifyToken("abc", VerificationOption{TargetScopes: []string{"scope"}, Action: "", Resource: "resource", Context: nil, NumRetry: &minus_one})
					Expect(err).To(BeNil())
					Expect(t).To(BeNil())
				})
			})

			Context("with an invalid json response when verifying token", func() {
				It("returns an error", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						var resp map[string]interface{}
						if r.RequestURI == "/" {
							resp = map[string]interface{}{"access_token": "def"}
							exp, _ := json.Marshal(resp)
							fmt.Fprintf(w, string(exp))
						} else if r.RequestURI == "/v" {
							Expect(r.Header.Get("Authorization")).To(Equal("Bearer def"))
							fmt.Fprintf(w, "bad")
						}
					}
					t, err := service.verifyToken("abc", VerificationOption{TargetScopes: []string{"scope"}, Action: "", Resource: "resource", Context: nil, NumRetry: &minus_one})
					Expect(err).NotTo(BeNil())
					Expect(t).To(BeNil())
				})
			})

			Context("with a proxy blocking the request", func() {
				It("returns an error getting token", func() {
					service.TokenURL = "http://sand.test"
					service.TokenVerifyURL = service.TokenURL + "/v"
					t, err := service.verifyToken("abc", VerificationOption{TargetScopes: []string{"scope"}, Action: "", Resource: "resource", Context: nil, NumRetry: &minus_one})
					Expect(t).To(BeNil())
					Expect(err).To(MatchError(AuthenticationError{Message: "oauth2: cannot fetch token: 403 Forbidden\nResponse: "}))
				})

				It("returns an error verifying token", func() {
					service.TokenVerifyURL = "http://sand.test/v"
					handler = func(w http.ResponseWriter, r *http.Request) {
						var resp map[string]interface{}
						if r.RequestURI == "/" {
							resp = map[string]interface{}{"access_token": "def"}
						} else if r.RequestURI == "/v" {
							Expect(r.Header.Get("Authorization")).To(Equal("Bearer def"))
							resp = map[string]interface{}{"allowed": true}
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					t, err := service.verifyToken("abc", VerificationOption{TargetScopes: []string{"scope"}, Action: "", Resource: "resource", Context: nil, NumRetry: &minus_one})
					Expect(t).To(BeNil())
					Expect(err).To(MatchError(AuthenticationError{Message: "Error response from the authentication service: 403 - "}))
				})
			})
		})
	})

	Describe("#expiryTime", func() {
		Context("with future expiration time", func() {
			It("returns the time difference", func() {
				futureTime := time.Now().Add(time.Duration(100) * time.Second)
				t := futureTime.Format("2006-01-02T15:04:05.00-07:00")
				Expect(service.expiryTime(t)).To(BeNumerically("<=", 100))
			})
		})

		Context("with past expiration time", func() {
			It("returns the default expiry time", func() {
				theTime := time.Now()
				t := theTime.Format("2006-01-02T15:04:05.00-07:00")
				Expect(service.expiryTime(t)).To(Equal(service.DefaultExpTime))

				theTime = time.Now().Add(time.Duration(-100) * time.Second)
				t = theTime.Format("2006-01-02T15:04:05.00-07:00")
				Expect(service.expiryTime(t)).To(Equal(service.DefaultExpTime))
			})
		})

		Context("with invalid time string", func() {
			It("returns the default expiry time", func() {
				Expect(service.expiryTime("a")).To(Equal(service.DefaultExpTime))
			})
		})
	})

	Describe("#buildOption", func() {
		BeforeEach(func() {
			service.Context = map[string]interface{}{"test": "default"}
		})
		Context("with prefilled option", func() {
			It("the option remains the same values", func() {
				numRetry := 3
				opt := VerificationOption{
					Resource:     "resource",
					Context:      map[string]interface{}{"test": "context"},
					TargetScopes: []string{"target"},
					NumRetry:     &numRetry,
					Action:       "action",
				}
				service.buildOption(&opt)
				Expect(opt.Resource).To(Equal("resource"))
				Expect(opt.Context["test"]).To(Equal("context"))
				Expect(opt.TargetScopes).To(Equal([]string{"target"}))
				Expect(opt.NumRetry).NotTo(BeNil())
				Expect(*opt.NumRetry).To(Equal(numRetry))
				Expect(opt.Action).To(Equal("action"))
			})
		})

		Context("without prefilled option", func() {
			It("uses the default values from service structs", func() {
				opt := VerificationOption{}
				service.buildOption(&opt)
				Expect(opt.Resource).To(Equal("r"))
				Expect(opt.Context["test"]).To(Equal("default"))
				Expect(opt.TargetScopes).To(BeEmpty())
				Expect(opt.NumRetry).NotTo(BeNil())
				Expect(*opt.NumRetry).To(Equal(0))
				Expect(opt.Action).To(Equal(""))
			})
		})
	})
})
