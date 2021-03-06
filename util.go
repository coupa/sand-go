package sand

import (
	"strings"

)

//ExtractToken extracts a bearer token from the Authorization header.
//The "bearer" keyword is case-insensitive
func ExtractToken(authHeader string) string {
	values := strings.Split(strings.Trim(authHeader, " "), " ")
	if len(values) > 1 && strings.ToLower(values[0]) == "bearer" {
		return values[1]
	}
	return ""
}
