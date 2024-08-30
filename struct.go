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
	// tagOptsSubjectID = []string{"prefix"}
	// tagOptsData      = []string{"replace"}
)

// Errors related to struct PII tag configuration
var (
	ErrInvalidTagConfiguration = errors.New("invalid tag configuration")

	ErrUnsupportedType         = errors.New("unsupported type must be a struct pointer")
	ErrUnsupportedFieldType    = errors.New("unsupported field type must be convertible to string")
	ErrMultipleNestedSubjectID = errors.New("potential multiple nested subject IDs")
	ErrSubjectIDNotFound       = errors.New("subject ID not found")
)

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
	name                    string
	isSub, isData, isNested bool
	prefix                  string
	replacement             string
	isSlice, isMap          bool
	nestedStructType        *piiStructType
	nestedStructTypeRef     reflect.Type
	rt                      reflect.Type
}

func (f piiField) getType(cache map[reflect.Type]*piiStructType) *piiStructType {
	if f.nestedStructTypeRef != nil {
		return cache[f.nestedStructTypeRef]
	}
	return f.nestedStructType
}

func (f piiField) IsZero() bool {
	return f == piiField{}
}

type piiStructType struct {
	valid     bool
	subField  piiField
	dataField []piiField
	rt        reflect.Type
}

type piiStruct struct {
	typ   piiStructType
	val   reflect.Value
	subID string
}

func ptr[T any](t T) *T {
	return &t
}

// resolveSubject resolves the PII struct subject ID value by walking through
// the struct and its nested PII fields.
//
// It returns an error if the subject ID is missing or duplicated.
func resolveSubject(pt piiStructType, pv reflect.Value) (string, error) {
	s := ""
	if !pt.subField.IsZero() {
		s = pt.subField.prefix + reflect.Indirect(pv.FieldByName(pt.subField.name)).String()
	}

	for _, piiF := range pt.dataField {
		if !piiF.isNested {
			continue
		}

		piiV := pv.FieldByName(piiF.name)
		if piiV.IsZero() {
			continue
		}

		cacheMu.Lock()
		piit := piiF.getType(cache)
		cacheMu.Unlock()
		if piit == nil {
			// TBD return error instead??
			panic(fmt.Errorf("failed to resolve PII field type. This should to be possible %v", piiF))
		}

		piiV = reflect.Indirect(pv.FieldByName(piiF.name))
		ss := ""
		switch {
		case piiF.isSlice:
			for i := 0; i < piiV.Len(); i++ {
				ss, _ = resolveSubject(*piit, piiV.Index(i))
				if ss != "" {
					break
				}
			}
		case piiF.isMap:
			for _, k := range piiV.MapKeys() {
				ss, _ = resolveSubject(*piit, piiV.MapIndex(k))
				if ss != "" {
					break
				}
			}
		default:
			ss, _ = resolveSubject(*piit, piiV)
		}

		if ss != "" {
			if s != "" && s != ss {
				return "", ErrMultipleNestedSubjectID
			}
			s = ss
		}
	}

	if s == "" {
		return "", ErrSubjectIDNotFound
	}
	return s, nil
}

func (ps *piiStruct) resolveSubject() (string, error) {
	if ps.subID == "" {
		var err error
		ps.subID, err = resolveSubject(ps.typ, ps.val)
		if err != nil {
			return "", err
		}
	}
	return ps.subID, nil
}

func (ps *piiStruct) subjectID() string {
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

func (s *piiStruct) replace(fn func(rf ReplaceField, fieldIdx int, val string) (string, error)) error {
	var (
		newVal string
		err    error
	)
	for idx, field := range s.typ.dataField {
		v := s.val.FieldByName(field.name)

		if v.IsZero() {
			continue
		}

		if !v.CanSet() {
			continue
		}
		elem := reflect.Indirect(v)

		if field.isData {
			val := elem.String()

			newVal, err = fn(ReplaceField{
				SubjectID:   s.subID,
				RType:       field.rt,
				Name:        field.name,
				Replacement: field.replacement,
			}, idx, val)
			if err != nil {
				return err
			}
			if newVal != val {
				elem.SetString(newVal)
			}
			continue
		}

		if field.isNested {
			var piit piiStructType

			cacheMu.Lock()
			piiT := field.getType(cache)
			cacheMu.Unlock()

			if piiT == nil {
				panic(fmt.Errorf("failed to resolve PII field type. This should to be possible %v", field))
			}
			piit = *piiT
			if !piiT.valid {
				continue
			}

			switch {
			case field.isSlice:
				for i := 0; i < elem.Len(); i++ {
					if err := (&piiStruct{
						subID: s.subID, // inherit parent subject ID
						val:   reflect.Indirect(elem.Index(i)),
						typ:   piit,
					}).replace(fn); err != nil {
						return err
					}
				}

			case field.isMap:
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
							subID: s.subID, // inherit parent subject ID
							val:   newElem,
							typ:   piit,
						}).replace(fn); err != nil {
							return err
						}

						elem.SetMapIndex(k, newElem)
						continue
					}

					if err := (&piiStruct{
						subID: s.subID,
						val:   reflect.Indirect(elem.MapIndex(k)),
						typ:   piit,
					}).replace(fn); err != nil {
						return err
					}
				}
			default:
				if err := (&piiStruct{
					subID: s.subID,
					val:   elem,
					typ:   piit,
				}).replace(fn); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

type piiMap map[int]*piiStruct

func (m piiMap) subjectIDs() []string {
	dedupMap := make(map[string]struct{})
	subIDs := []string{}
	for _, s := range m {
		subID := s.subjectID()
		if _, ok := dedupMap[subID]; ok {
			continue
		}
		dedupMap[subID] = struct{}{}
		subIDs = append(subIDs, subID)
	}

	return subIDs
}

func parseTag(tagStr string) (name string, optVals map[string]string) {
	if tagStr == "" {
		return
	}

	tags := strings.Split(tagStr, ",")

	name = strings.TrimSpace(tags[0])

	optVals = make(map[string]string)
	for _, opt := range tags[1:] {
		splits := strings.Split(opt, "=")
		if len(splits) == 2 {
			name, val := strings.TrimSpace(splits[0]), strings.TrimSpace(splits[1])
			optVals[name] = val
		}
	}

	return
}

func scanStruct(rt reflect.Type) (piiStructType, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if _, ok := cache[rt]; !ok {
		c := piiStructContext{seen: cache}
		piit, err := scanStructWithContext(c, rt)
		if err != nil {
			return piiStructType{}, err
		}
		cache[rt] = &piit
	}

	return *cache[rt], nil
}

func scanStructWithContext(c piiStructContext, rt reflect.Type) (piiStructType, error) {
	piiFields := make([]piiField, 0)
	var subjectField piiField
	for i := 0; i < rt.NumField(); i++ {
		v := rt.Field(i)
		tags := v.Tag.Get(tagID)
		if tags == "" {
			continue
		}

		vv, _ := rt.FieldByName(v.Name)
		if !vv.IsExported() {
			continue
		}

		name, opts := parseTag(tags)
		piiF := piiField{
			name:        v.Name,
			isSub:       name == tagSubjectID,
			isData:      name == tagData,
			isNested:    name == tagDive,
			prefix:      opts["prefix"],
			replacement: opts["replace"],
			rt:          v.Type,
		}

		switch {
		case piiF.isSub:
			// if v.Type.Kind() != reflect.String {
			// 	continue
			// }
			if !v.Type.ConvertibleTo(stringType) {
				return piiStructType{}, ErrUnsupportedFieldType
			}

			if !subjectField.IsZero() {
				return piiStructType{}, ErrMultipleNestedSubjectID
			}
			subjectField = piiF

		case piiF.isData:
			tt := v.Type
			if tt.Kind() == reflect.Ptr {
				tt = tt.Elem()
			}
			if tt.Kind() != reflect.String {
				continue
			}
			piiFields = append(piiFields, piiF)

		case piiF.isNested:
			tt := vv.Type
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
				var ppiit piiStructType
				var err error
				c.seen[tt] = &ppiit
				ppiit, err = scanStructWithContext(c, tt)
				if err != nil {
					return piiStructType{}, err
				}
				piiF.nestedStructType = &ppiit
			} else {
				piiF.nestedStructTypeRef = tt
			}

			piiFields = append(piiFields, piiF)
		}
	}

	return piiStructType{
		valid:     len(piiFields) > 0,
		subField:  subjectField,
		dataField: piiFields,
		rt:        rt,
	}, nil
}

func scan(values ...any) (indexes piiMap, err error) {
	indexes = make(map[int]*piiStruct, len(values))

	defer func() {
		if err != nil {
			err = errors.Join(ErrInvalidTagConfiguration, err)
		}
	}()

	for idx, v := range values {
		v := v
		val := reflect.ValueOf(v)

		if val.Kind() != reflect.Ptr {
			return nil, fmt.Errorf("%w at #%d", ErrUnsupportedType, idx)
		}
		ift := reflect.Indirect(val).Type()
		if ift.Kind() != reflect.Struct {
			return nil, fmt.Errorf("%w at #%d", ErrUnsupportedType, idx)
		}

		elem := val.Elem()

		piiType, err := scanStruct(ift)
		if err != nil {
			return nil, err
		}
		if !piiType.valid {
			continue
		}

		piiStruct := &piiStruct{
			typ: piiType,
			val: elem,
		}

		if _, err := piiStruct.resolveSubject(); err != nil {
			return nil, err
		}

		indexes[idx] = piiStruct
	}

	return indexes, nil
}
