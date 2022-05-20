package core

type Key string

func (k Key) String() string {
	return "KEY-*****"
}

type KeyMap map[string]Key

func NewKeyMap() KeyMap {
	return make(map[string]Key)
}

func (km KeyMap) IDs() []string {
	subIDs := []string{}
	for subID := range km {
		subIDs = append(subIDs, subID)
	}
	return subIDs
}

type IDKey struct {
	id  string
	key Key
}

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
