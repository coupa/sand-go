package sand_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestSandGo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Sand Suite")
}
