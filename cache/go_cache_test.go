package cache_test

import (
	"time"

	. "github.com/coupa/sand-go/cache"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("GoCache", func() {
	var goCache *GoCache
	BeforeEach(func() {
		goCache = NewGoCache(1*time.Hour, 1*time.Second)
	})
	Describe("Read", func() {
		It("reads values from the cache", func() {
			Expect(goCache.Read("test")).To(BeNil())

			goCache.Write("test", "hello", time.Duration(0))
			Expect(goCache.Read("test")).To(Equal("hello"))

			Expect(goCache.Read("test2")).To(BeNil())

			goCache.Write("test3", "hello2", time.Duration(0))
			Expect(goCache.Read("test3")).To(Equal("hello2"))
			Expect(goCache.Read("test2")).To(BeNil())
		})
	})

	Describe("Write", func() {
		It("setting expiry time 0 means no expiration and not default expiration time", func() {
			goCache = NewGoCache(10*time.Millisecond, 1*time.Millisecond)

			goCache.Write("test", "hello", 1*time.Millisecond)
			time.Sleep(10 * time.Millisecond)
			Expect(goCache.Read("test")).To(BeNil())

			goCache.Write("test", "hello", time.Duration(0))
			time.Sleep(10 * time.Millisecond)
			Expect(goCache.Read("test")).To(Equal("hello"))
		})
	})

	Describe("Delete", func() {
		It("deletes an item from the cache", func() {
			goCache.Write("test", "hello", time.Duration(0))
			Expect(goCache.Read("test")).To(Equal("hello"))
			goCache.Write("test2", "hello2", time.Duration(0))
			Expect(goCache.Read("test2")).To(Equal("hello2"))

			goCache.Delete("test2")
			Expect(goCache.Read("test")).To(Equal("hello"))
			Expect(goCache.Read("test2")).To(BeNil())

			goCache.Delete("test")
			Expect(goCache.Read("test")).To(BeNil())
		})
	})

	Describe("Clear", func() {
		It("clears all items from the cache", func() {
			goCache.Write("test", "hello", time.Duration(0))
			Expect(goCache.Read("test")).To(Equal("hello"))
			goCache.Write("test2", "hello2", time.Duration(0))
			Expect(goCache.Read("test2")).To(Equal("hello2"))

			goCache.Clear()
			Expect(goCache.Read("test")).To(BeNil())
			Expect(goCache.Read("test2")).To(BeNil())
		})
	})
})
