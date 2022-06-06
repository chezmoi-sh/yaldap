package yaml

import (
	"fmt"
	"strconv"
	"strings"

	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
)

const (
	// AttributePrefix is the prefix used to determine which YAML are LDAP attributes.
	AttributePrefix = ".@"
)

// ParseError describes a failure occurring during the parsing of the YAML definition.
type ParseError error

func parseObject(dn string, obj map[string]interface{}, index map[string]*Object) (*Object, error) {
	object := &Object{
		dn:         dn,
		children:   map[string]*Object{},
		attributes: yaldaplib.Attributes{},
	}
	index[dn] = object

	for key, obj := range obj {
		if strings.HasPrefix(key, AttributePrefix) {
			key = strings.TrimPrefix(key, AttributePrefix)
			values, err := parseAttributeValue(key, obj)
			if err != nil {
				return nil, ParseError(fmt.Errorf("failed to get attribute on %s: %w", dn, err))
			}
			object.attributes[key] = values
			continue
		}

		obj, valid := obj.(map[string]interface{})
		if !valid {
			return nil, ParseError(fmt.Errorf("invalid field '%s' on %s: must be an object", key, dn))
		}

		if !strings.ContainsRune(key, ':') {
			return nil, ParseError(fmt.Errorf("invalid field '%s' on %s: should contains the object type (ou, cn, ...)", key, dn))
		}

		sp := strings.SplitN(key, ":", 2)
		key = strings.Join(sp, "=")
		subdn := strings.TrimSuffix(key+","+dn, ",")

		var err error
		object.children[key], err = parseObject(subdn, obj, index)
		if err != nil {
			return nil, err
		}

		object.children[key].attributes[sp[0]] = &Attribute{sp[1]}
	}
	return object, nil
}

func parseAttributeValue(key string, obj interface{}) (*Attribute, error) {
	switch value := obj.(type) {
	case []string:
		return (*Attribute)(&value), nil

	case []interface{}:
		var values Attribute

		for idx, sval := range value {
			switch sval := sval.(type) {
			case string:
				values = append(values, sval)
			case int:
				values = append(values, strconv.Itoa(sval))
			case bool:
				values = append(values, strconv.FormatBool(sval))
			default:
				return nil, ParseError(fmt.Errorf("invalid attribute type '%T' on attribute '%s[%d]'", sval, key, idx))
			}
		}
		return &values, nil

	case string:
		return &Attribute{value}, nil
	case int:
		return &Attribute{strconv.Itoa(value)}, nil
	case bool:
		return &Attribute{strconv.FormatBool(value)}, nil

	default:
		return nil, ParseError(fmt.Errorf("invalid attribute type '%T' on attribute '%s'", value, key))
	}
}
