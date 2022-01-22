package gcpsigner

import "fmt"

// KeySpec is a utility to allow easy formattig of the key name
// that is used in KMS
type KeySpec struct {
	// Project is the name of your porject, such as "project-1234"
	Project string
	// Location is the name of the location your key belongs to, such as "us-central1"
	Location string
	// KeyRing is the name of your key ring
	KeyRing string
	// Key is the name of your key
	Key string
	// Version is the verson of your key. Defaults to 1
	Version int
}

func (ks KeySpec) String() string {
	version := ks.Version
	if version <= 0 {
		version = 1
	}
	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%d", ks.Project, ks.Location, ks.KeyRing, ks.Key, version)
}
