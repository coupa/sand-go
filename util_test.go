package sand_test

import (
	. "github.com/coupa/sand-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Util", func() {
	Describe("#ExtractToken", func() {
		Context("with invalid bearer string", func() {
			It("should return the empty string", func() {
				tests := []string{"", " ", "abc", "abc ", "bearer ", "Bearer ", "bear abc"}
				for _, t := range tests {
					Expect(ExtractToken(t)).To(Equal(""))
				}
			})
		})
		Context("with valid bearer string", func() {
			It("should return the token", func() {
				tests := []string{"Bearer abc", "bearer abc", " Bearer abc", " bearer abc", " Bearer abc d "}
				for _, t := range tests {
					Expect(ExtractToken(t)).To(Equal("abc"))
				}
			})
		})
	})
})
