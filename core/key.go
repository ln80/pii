package core

// Encryption key lifecycle states.
const (
	StateActive   = "ACTIVE"
	StateDisabled = "DISABLED"
	StateDeleted  = "DELETED"
)

// KeyState presents encryption key lifecycle states
type KeyState string

// Key presents the plain text value of an encryption key
type Key string

// String overwrites the default to string behavior to protect the key sensitive value.
func (k Key) String() string {
	return "KEY-*****"
}

// KeyMap presents a map of Keys indexed by keyID.
type KeyMap map[string]Key

// NewKeyMap returns a new empty KeyMap.
func NewKeyMap() KeyMap {
	return make(map[string]Key)
}

// KeyIDs returns Key IDs.
func (km KeyMap) KeyIDs() []string {
	subIDs := []string{}
	for subID := range km {
		subIDs = append(subIDs, subID)
	}
	return subIDs
}

// IDKey presents a pair to combine a Key and its ID.
type IDKey struct {
	id  string
	key Key
}

// NewIDKey returns new IdKey value of the given Key and ID.
func NewIDKey(id, key string) IDKey {
	return IDKey{
		id, Key(key),
	}
}

func (ik IDKey) ID() string {
	return ik.id
}

func (ik IDKey) Key() Key {
	return ik.key
}
