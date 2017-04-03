# sand-go
Go library for service authentication via OAuth2

A client who wants to communicate with a service, it will request a token from the OAuth2 server and use this token to make an API call to the service.

When a service receives a request with an OAuth bearer token, it verifies the token with the OAuth2 server to see if the token is allowed to access this service. The service acts like an OAuth2 Resource Server that verifies the token.

## Features

* The authentication is performed using the "client credentials" grant type in OAuth2.
* The tokens can be cached on both the client and the service sides. The cache store is configurable by providing an adapter to the cache interface.

## Instruction

A client that intends to communicate with a service can use sand.Client to request a token from an OAuth2 server. A client can be created via the `NewClient` function:

```
//ClientID: The client ID of the OAuth2 client credentials
//ClientSecret: The client secret of the OAuth2 client credentials
//TokenURL: The token endpoint of the OAuth2 server, e.g., "https://oauth.example.com/oauth2/token"
client := sand.NewClient("ClientID", "ClientSecret", "TokenURL")

//Below shows the optional fields (with their default values) that can be modified after a client is created
client.SkipTLSVerify = false   // Skip verifying the TLS certificate
client.MaxRetry      = 5       // Maximum number of retries on connection error
client.Cache         = nil     // A cache that conforms to the sand.Cache interface
client.CacheRoot     = "sand"  // A string as the root namespace in the cache

// The Request function has the retry mechanism to retry on 401 error.
client.Request("cache-key", []string{"scope1", "scope2"}, func(token string) (*http.Response, error) {
  // Make http request with "Bearer {token}" in the Authorization header
  // return the response and error
})
```

A service that receives a request with the OAuth2 bearer token can use sand.Service to authorize the token with the OAuth2 server. A service can be created via the `NewService` function:

```
//The first four arguments are the same as those of sand.NewClient
//Resource: The resource name that identifies this service and is registered with the OAuth2 server
//TokenVerifyURL: The URL of the token verification endpoint, e.g., "https://oauth.example.com/warden/token/allowed"
service := sand.NewService("ClientID", "ClientSecret", "TokenURL", "Resource", "TokenVerifyURL", []string{"Scopes"})

//Below shows the optional field (with the default value) that can be modified after a service is created
... // Same fields as client's above
service.DefaultExpTime = 3600,  # The default expiry time for cache for invalid tokens and also valid tokens which have no expiry times.

//Usage Example with Gin:
func(c *gin.Context) {
  response, err := sandService.CheckRequest(c.Request, []string{"scope1", "scope2"}, "action")
  if err != nil || response["allowed"] != true {
    c.JSON(sandService.ErrorCode(err), err)
  }
  ...
}
```

### Client

sand.Client has the `Request` method which can perform retry when encountering 401 responses from the service. This should be the primary method to use for a client.

Both sand.Client and sand.Service have the `Token` function that gets an OAuth token from authentication service. If a cache store is available and the token is found in cache, it will return this token and not retrieving the token from the authentication service.

### Service

sand.Service defines the `CheckRequest` function for verifying an http.Request with the authentication service on whether the client token in the request is allowed to communicate with this service. A client's token and the verification result will also be cached if the cache is available.
