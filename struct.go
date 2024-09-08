package pii

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

var (
	tagID        = "pii"
	tagSubjectID = "subjectID"
	tagData      = "data"
	tagDive      = "dive"
)

var (
	ErrInvalidTagConfiguration = errors.New("invalid 'pii' tag configuration")
	ErrUnsupportedType         = errors.New("unsupported type")
	ErrUnsupportedFieldType    = errors.New("unsupported field type must be convertible to string")
	ErrMultipleNestedSubjectID = errors.New("potential multiple nested subject IDs")
	ErrSubjectIDNotFound       = errors.New("subject ID not found")
	ErrRedactFuncNotFound      = errors.New("redact function not found")
)

// Check if a struct value contains PII.
//
// It fails if "pii" tag is misconfigured or value is not a struct or pointer to struct.
func Check(v any) (bool, error) {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false, fmt.Errorf("%w : %v", ErrUnsupportedType, t)
	}

	piiStructType, err := scanStructType(t)
	if err != nil {
		return false, err
	}

	return piiStructType.hasPII, nil
}

type RedactConfig struct {
	RedactFunc ReplaceFunc
}

// Redact does redact PII data from the struct field values.
//
// It fails if 'structPtr' is not a struct pointer, the pii tag is misconfigured,
// or the redact function is nil.
//
// Optionally, it accepts overriding the default redact function.
func Redact(structPtr any, opts ...func(*RedactConfig)) error {
	cfg := RedactConfig{
		RedactFunc: defaultRedactFunc,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&cfg)
	}
	if cfg.RedactFunc == nil {
		return ErrRedactFuncNotFound
	}

	piiStruct, err := scan(structPtr, false)
	if err != nil {
		return err
	}

	if !piiStruct.typ.hasPII {
		return nil
	}

	return piiStruct.replace(cfg.RedactFunc)
}

var defaultRedactFunc ReplaceFunc = func(_ ReplaceField, val string) (string, error) {
	runes := []rune(val)
	switch l := len(val); {
	case l == 0:
		return val, nil
	case l > 6:
		for i := 1; i < l-2; i++ {
			runes[i] = '*'
		}

	case l > 3:
		for i := 0; i < l-1; i++ {
			runes[i] = '*'
		}
	default:
		for i := 0; i < l; i++ {
			runes[i] = '*'
		}
	}
	return string(runes), nil
}

var (
	stringType = reflect.TypeOf("")
)

var (
	cache   map[reflect.Type]*piiStructType = make(map[reflect.Type]*piiStructType)
	cacheMu sync.RWMutex
)

type piiStructContext struct {
	seen map[reflect.Type]*piiStructType
}

type piiField struct {
	sf                      reflect.StructField
	isSub, isData, isNested bool
	prefix                  string
	replacement             string
	isSlice, isMap          bool
	nestedStructType        *piiStructType
	nestedStructTypeRef     reflect.Type
}

func (f piiField) getType(cache map[reflect.Type]*piiStructType) *piiStructType {
	if f.nestedStructTypeRef != nil {
		return cache[f.nestedStructTypeRef]
	}
	return f.nestedStructType
}

func (f piiField) IsZero() bool {
	// TBD find a better condition??
	return f.sf.Name == ""
}

type piiStructType struct {
	hasPII    bool
	subField  piiField
	piiFields []piiField
	rt        reflect.Type
}

type piiStruct struct {
	typ       piiStructType
	val       reflect.Value
	subjectID string
}

func ptr[T any](t T) *T {
	return &t
}

// resolveSubject resolves the PII struct subject ID value by walking through
// the struct and its nested PII structs.
//
// It returns an error if the subject ID is missing or duplicated.
func resolveSubject(pt piiStructType, pv reflect.Value) (string, error) {
	subject := ""
	if !pt.subField.IsZero() {
		subject = pt.subField.prefix + reflect.Indirect(pv.FieldByIndex(pt.subField.sf.Index)).String()
	}

	for _, piiF := range pt.piiFields {
		if !piiF.isNested {
			continue
		}

		piiFV := pv.FieldByIndex(piiF.sf.Index)
		if piiFV.IsZero() {
			continue
		}

		cacheMu.Lock()
		piiT := piiF.getType(cache)
		cacheMu.Unlock()
		if piiT == nil {
			// TBD return error instead ??
			panic(fmt.Errorf("unexpected: failed to resolve PII field type %v", piiF))
		}

		piiFV = reflect.Indirect(piiFV)
		nestedSubject := ""
		switch {
		case piiF.isSlice:
			for i := 0; i < piiFV.Len(); i++ {
				nestedSubject, _ = resolveSubject(*piiT, piiFV.Index(i))
				if nestedSubject != "" {
					break
				}
			}
		case piiF.isMap:
			for _, k := range piiFV.MapKeys() {
				nestedSubject, _ = resolveSubject(*piiT, piiFV.MapIndex(k))
				if nestedSubject != "" {
					break
				}
			}
		default:
			nestedSubject, _ = resolveSubject(*piiT, piiFV)
		}

		if nestedSubject != "" {
			if subject != "" && subject != nestedSubject {
				return "", ErrMultipleNestedSubjectID
			}
			subject = nestedSubject
		}
	}

	if subject == "" {
		return "", fmt.Errorf("%w: %v", ErrSubjectIDNotFound, pt.rt)
	}
	return subject, nil
}

func (ps *piiStruct) resolveSubject() (string, error) {
	if ps.subjectID == "" {
		var err error
		ps.subjectID, err = resolveSubject(ps.typ, ps.val)
		if err != nil {
			return "", err
		}
	}
	return ps.subjectID, nil
}

func (ps *piiStruct) getSubjectID() string {
	s, err := ps.resolveSubject()
	if err != nil {
		panic(err)
	}
	return s
}

type ReplaceField struct {
	SubjectID   string
	Name        string
	RType       reflect.Type
	Replacement string
}

type ReplaceFunc func(rf ReplaceField, val string) (string, error)

func (s *piiStruct) replace(fn ReplaceFunc) error {
	var (
		newVal string
		err    error
	)
	for _, piiF := range s.typ.piiFields {
		v := s.val.FieldByIndex(piiF.sf.Index)

		if v.IsZero() {
			continue
		}

		if !v.CanSet() {
			continue
		}
		elem := reflect.Indirect(v)

		if piiF.isData {
			val := elem.String()

			newVal, err = fn(ReplaceField{
				SubjectID:   s.subjectID,
				RType:       piiF.sf.Type,
				Replacement: piiF.replacement,
			}, val)
			if err != nil {
				return err
			}
			if newVal != val {
				elem.SetString(newVal)
			}
			continue
		}

		if piiF.isNested {
			var piiT piiStructType

			cacheMu.Lock()
			piiTPtr := piiF.getType(cache)
			cacheMu.Unlock()

			if piiTPtr == nil {
				panic(fmt.Errorf("unexpected: failed to resolve PII field type %v", piiF))
			}
			piiT = *piiTPtr
			if !piiT.hasPII {
				continue
			}

			switch {
			case piiF.isSlice:
				for i := 0; i < elem.Len(); i++ {
					if err := (&piiStruct{
						subjectID: s.subjectID, // inherit parent subject ID
						val:       reflect.Indirect(elem.Index(i)),
						typ:       piiT,
					}).replace(fn); err != nil {
						return err
					}
				}

			case piiF.isMap:
				for _, k := range elem.MapKeys() {
					mapElem := elem.MapIndex(k)
					if mapElem.IsZero() {
						continue
					}
					mapElem = reflect.Indirect(elem.MapIndex(k))
					if !mapElem.CanAddr() {
						newElem := reflect.New(mapElem.Type()).Elem()
						newElem.Set(mapElem)

						if err := (&piiStruct{
							subjectID: s.subjectID, // inherit parent subject ID
							val:       newElem,
							typ:       piiT,
						}).replace(fn); err != nil {
							return err
						}

						elem.SetMapIndex(k, newElem)
						continue
					}

					if err := (&piiStruct{
						subjectID: s.subjectID,
						val:       reflect.Indirect(elem.MapIndex(k)),
						typ:       piiT,
					}).replace(fn); err != nil {
						return err
					}
				}
			default:
				if err := (&piiStruct{
					subjectID: s.subjectID,
					val:       elem,
					typ:       piiT,
				}).replace(fn); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func parseTag(tagStr string) (name string, opts map[string]string) {
	if tagStr == "" {
		return
	}

	tags := strings.Split(tagStr, ",")
	name = strings.TrimSpace(tags[0])
	opts = make(map[string]string)
	for _, opt := range tags[1:] {
		splits := strings.Split(opt, "=")
		if len(splits) == 2 {
			name, val := strings.TrimSpace(splits[0]), strings.TrimSpace(splits[1])
			opts[name] = val
		}
	}
	return
}

func scanStructType(rt reflect.Type) (piiStructType, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if _, ok := cache[rt]; !ok {
		c := piiStructContext{seen: cache}
		piiT, err := scanStructTypeWithContext(c, rt)
		if err != nil {
			return piiStructType{}, err
		}
		cache[rt] = &piiT
	}

	return *cache[rt], nil
}

func scanStructTypeWithContext(c piiStructContext, rt reflect.Type) (piiStructType, error) {
	piiFields := make([]piiField, 0)
	var subjectField piiField
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		tags := field.Tag.Get(tagID)
		if tags == "" {
			continue
		}

		if !field.IsExported() {
			continue
		}

		name, opts := parseTag(tags)
		piiF := piiField{
			sf:          field,
			isSub:       name == tagSubjectID,
			isData:      name == tagData,
			isNested:    name == tagDive,
			prefix:      opts["prefix"],
			replacement: opts["replace"],
		}

		switch {
		case piiF.isSub:
			if !field.Type.ConvertibleTo(stringType) {
				return piiStructType{}, ErrUnsupportedFieldType
			}

			if !subjectField.IsZero() {
				return piiStructType{}, ErrMultipleNestedSubjectID
			}
			subjectField = piiF

		case piiF.isData:
			tt := field.Type
			if tt.Kind() == reflect.Ptr {
				tt = tt.Elem()
			}
			if tt.Kind() != reflect.String {
				continue
			}
			piiFields = append(piiFields, piiF)

		case piiF.isNested:
			tt := field.Type
			if tt.Kind() == reflect.Ptr {
				tt = tt.Elem()
			}
			if tt.Kind() == reflect.Slice {
				piiF.isSlice = true
				tt = tt.Elem()
			}
			if tt.Kind() == reflect.Map {
				piiF.isMap = true
				tt = tt.Elem()
			}
			if tt.Kind() == reflect.Ptr {
				tt = tt.Elem()
			}

			_, seen := c.seen[tt]
			if !seen {
				var piiType piiStructType
				var err error
				c.seen[tt] = &piiType
				piiType, err = scanStructTypeWithContext(c, tt)
				if err != nil {
					return piiStructType{}, err
				}
				piiF.nestedStructType = &piiType
			} else {
				piiF.nestedStructTypeRef = tt
			}

			piiFields = append(piiFields, piiF)
		}
	}

	return piiStructType{
		hasPII:    len(piiFields) > 0,
		subField:  subjectField,
		piiFields: piiFields,
		rt:        rt,
	}, nil
}

func scan(v any, requireSubject bool) (piiStr piiStruct, err error) {
	defer func() {
		if err != nil {
			err = errors.Join(ErrInvalidTagConfiguration, err)
		}
	}()

	if v == nil {
		err = fmt.Errorf("%w: %v", ErrUnsupportedType, nil)
		return
	}

	tt := reflect.TypeOf(v)
	if tt.Kind() != reflect.Pointer {
		err = fmt.Errorf("%w: %v", ErrUnsupportedType, tt)
		return
	}
	if tt.Kind() == reflect.Pointer {
		tt = tt.Elem()
	}
	if tt.Kind() != reflect.Struct {
		err = fmt.Errorf("%w: %v", ErrUnsupportedType, tt)
		return
	}

	var piiType piiStructType
	piiType, err = scanStructType(tt)
	if err != nil {
		return
	}
	if !piiType.hasPII {
		// As struct doesn't have PII data, no need to proceed and resolve subject ID value
		// that's solely used to get encryption materials to encrypt/decrypt PII fields.
		// Therefore getting calling 'reflect.ValueOf', considering its cost, doesn't make sense.
		piiStr = piiStruct{
			typ: piiType,
		}
		return
	}

	piiStr = piiStruct{
		typ: piiType,
		val: reflect.ValueOf(v).Elem(),
	}

	if requireSubject {
		if _, err = piiStr.resolveSubject(); err != nil {
			return
		}
	}
	return
}
