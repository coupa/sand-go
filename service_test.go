package sand

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Service", func() {
	var service *Service

	BeforeEach(func() {
		service, _ = NewService("i", "s", "u", "r", "/v")
		service.MaxRetry = 0
	})

	Describe("#NewService", func() {
		It("gives error when missing required arguments", func() {
			_, err := NewService("", "s", "u", "r", "/v")
			Expect(err.Error()).To(Equal("NewService: missing required argument(s)"))
			_, err = NewService("i", "s", "u", "", "/v")
			Expect(err.Error()).To(Equal("NewService: missing required argument(s)"))
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
				It("returns false with no error", func() {
					r := http.Request{Header: http.Header{}}
					r.Header.Set("Authorization", "")
					t, err := service.CheckRequest(&r, "")
					Expect(t).To(Equal(false))
					Expect(err).To(BeNil())

					r.Header.Set("Authorization", "bad bearer token")
					t, err = service.CheckRequest(&r, "")
					Expect(t).To(Equal(false))
					Expect(err).To(BeNil())
				})
			})

			Context("with service unable to retrieve an access token", func() {
				It("returns an error of type sand.AuthenticationError", func() {
					service.TokenURL = ""
					r := http.Request{Header: http.Header{}}
					r.Header.Set("Authorization", "Bearer abc")
					t, err := service.CheckRequest(&r, "")
					Expect(t).To(Equal(false))
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
					t, err := service.CheckRequest(&r, "")
					Expect(t).To(Equal(false))
					_, yes := err.(AuthenticationError)
					Expect(yes).To(BeTrue())
				})
			})
		})

		Describe("#isTokenAllowed", func() {
			Context("with empty token", func() {
				It("returns false", func() {
					t, err := service.isTokenAllowed("", "")
					Expect(t).To(Equal(false))
					Expect(err).To(BeNil())
				})
			})

			Context("with an error response", func() {
				It("returns a connection error", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusNotFound)
					}
					t, err := service.isTokenAllowed("abc", "")
					Expect(t).To(Equal(false))
					_, yes := err.(AuthenticationError)
					Expect(yes).To(BeTrue())
				})
			})

			Context("with allowed response", func() {
				It("returns true", func() {
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
					t, err := service.isTokenAllowed("abc", "")
					Expect(t).To(Equal(true))
					Expect(err).To(BeNil())
				})
			})

			Context("with not allowed response", func() {
				It("returns false", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
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
					t, err := service.isTokenAllowed("abc", "")
					Expect(t).To(Equal(false))
					Expect(err).To(BeNil())
				})
			})

			Context("with empty response", func() {
				It("returns false", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						var resp map[string]interface{}
						if r.RequestURI == "/" {
							resp = map[string]interface{}{"access_token": "def"}
						} else if r.RequestURI == "/v" {
							Expect(r.Header.Get("Authorization")).To(Equal("Bearer def"))
							resp = map[string]interface{}{}
						}
						exp, _ := json.Marshal(resp)
						fmt.Fprintf(w, string(exp))
					}
					t, err := service.isTokenAllowed("abc", "")
					Expect(t).To(Equal(false))
					Expect(err).To(BeNil())
				})
			})
		})

		Describe("#verifyToken", func() {
			Context("with empty token", func() {
				It("returns nil", func() {
					t, err := service.verifyToken("", "")
					Expect(t).To(BeNil())
					Expect(err).To(BeNil())
				})
			})

			Context("with an error response", func() {
				It("returns an error", func() {
					handler = func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusNotFound)
					}
					t, err := service.verifyToken("abc", "")
					Expect(t).To(BeNil())
					_, yes := err.(AuthenticationError)
					Expect(yes).To(BeTrue())
				})
			})

			Context("with a valid token and valid response", func() {
				It("returns allowed is true", func() {
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
					t, err := service.verifyToken("abc", "")
					Expect(err).To(BeNil())
					Expect(t["allowed"]).To(Equal(true))
				})
			})

			Context("with an invalid json response when verifying token", func() {
				It("", func() {
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
					t, err := service.verifyToken("abc", "")
					Expect(err).NotTo(BeNil())
					Expect(t).To(BeNil())
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
})
