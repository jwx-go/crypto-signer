//go:generate ./gen.sh

package gcpsigner

// Cache is used internally to store items that are frequently
// accessed. In particular, the public key is accessed for both
// signing _and_ verifying, and is cached if you provide storage for it.
type Cache interface {
	Get(interface{}) (interface{}, bool)
	Set(interface{}, interface{})
}
