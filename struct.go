package pii

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

var (
	tagID            = "pii"
	tagSubjectID     = "subjectID"
	tagData          = "data"
	tagOptsSubjectID = []string{"prefix"}
	tagOptsData      = []string{"replace"}
)

var (
	ErrUnsupportedType = errors.New("unsupported type, must be a struct pointer")

	ErrInvalidTagConfiguration = errors.New("invalid tag configuration")
	errSubjectIDNotfound       = errors.New("subjectID not found")
	errSubjectIDManyDefinition = errors.New("subjectID defined multiple time")
)

type piiStruct struct {
	index        int
	reflectValue reflect.Value
	subID        string
	prefix       string
	fields       []string
	replacements []string
}

func (ps *piiStruct) subjectID() string {
	return ps.prefix + ps.subID
}

func (s *piiStruct) replace(fn func(fieldIdx int, val string) (string, error)) error {
	for idx, field := range s.fields {
		el := reflect.Indirect(s.reflectValue.FieldByName(field))
		switch el.Kind() {
		case reflect.String:
			if el.CanSet() {
				newVal, err := fn(idx, el.String())
				if err != nil {
					return err
				}
				el.SetString(newVal)
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

func indexOfOpt(optName string, opts []string) int {
	for k, v := range opts {
		if optName == v {
			return k
		}
	}
	return -1
}

func parseTag(tagStr, name string, opts []string) (ok bool, optVals []string) {
	if tagStr == "" {
		return
	}

	tags := strings.Split(tagStr, ",")
	ok = strings.TrimSpace(tags[0]) == name
	optCount := len(opts)

	if !ok || optCount == 0 {
		return
	}

	optVals = make([]string, optCount)
	for _, opt := range tags[1:] {
		splits := strings.Split(opt, "=")
		if len(splits) == 2 {
			name, val := strings.TrimSpace(splits[0]), strings.TrimSpace(splits[1])
			if idx := indexOfOpt(name, opts); idx != -1 {
				optVals[idx] = val
			}
		}
	}

	return
}

func scan(values ...interface{}) (indexes piiMap, err error) {
	indexes = make(map[int]*piiStruct)

	defer func() {
		if err != nil && !errors.Is(ErrUnsupportedType, err) {
			err = fmt.Errorf("%w: %v", ErrInvalidTagConfiguration, err)
		}
	}()

	for idx, v := range values {
		v := v
		val := reflect.ValueOf(v)
		if val.Kind() != reflect.Ptr {
			return nil, ErrUnsupportedType
		}
		ift := reflect.Indirect(val).Type()
		if ift.Kind() != reflect.Struct {
			return nil, ErrUnsupportedType
		}

		elem := val.Elem()
		for i := 0; i < ift.NumField(); i++ {
			v := ift.Field(i)
			el := reflect.Indirect(elem.FieldByName(v.Name))
			switch el.Kind() {
			case reflect.String:
				if el.CanSet() {
					tags := v.Tag.Get(tagID)
					input := el.String()

					if ok, opts := parseTag(tags, tagSubjectID, tagOptsSubjectID); ok {
						if vidx, ok := indexes[idx]; ok {
							if vidx.subID != "" {
								return nil, fmt.Errorf("%w: at #%d", errSubjectIDManyDefinition, idx)
							} else {
								vidx.subID = input
							}
						} else {
							indexes[idx] = &piiStruct{
								index:  idx,
								subID:  input,
								prefix: opts[0],
								fields: []string{},
							}
						}
					} else if ok, opts = parseTag(tags, tagData, tagOptsData); ok {
						if _, ok := indexes[idx]; !ok {
							indexes[idx] = &piiStruct{
								index:  idx,
								fields: []string{},
							}
						}
						indexes[idx].fields = append(indexes[idx].fields, v.Name)
						indexes[idx].replacements = append(indexes[idx].replacements, opts[0])
					}
				}
			}
		}

		// case of current values does not have pii tag configured
		if _, ok := indexes[idx]; !ok {
			continue
		}

		// return an error if a struct does not have subject id
		if indexes[idx].subID == "" {
			return nil, fmt.Errorf("%w: at #%d", errSubjectIDNotfound, idx)
		}

		// ignore struct if it does not have personal fields
		if len(indexes[idx].fields) == 0 {
			delete(indexes, idx)
		}

		indexes[idx].reflectValue = elem
	}

	return indexes, nil
}
