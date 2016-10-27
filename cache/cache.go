package cache

import "time"

//Cache is an interface for caches
type Cache interface {
	Read(string) interface{}
	Write(string, interface{}, time.Duration) error
	Delete(string)
	Clear()
}
