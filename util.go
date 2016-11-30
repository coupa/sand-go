package sand

import (
	"strings"

	"github.com/Sirupsen/logrus"
)

var (
	//Logger is used to log detail errors
	Logger = logrus.New()
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
