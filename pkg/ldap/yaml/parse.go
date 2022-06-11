package yaml

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
)

const (
	// AttributePrefix prefixes LDAP attributes.
	AttributePrefix = ".@"
	// PropertyPrefix prefixes all internal yaLDAP properties that used internally.
	PropertyPrefix           = ".#"
	PropertyBindPasswordAttr = PropertyPrefix + "BindPasswordAttr"
	PropertyAllowedDN        = PropertyPrefix + "AllowedDN"
	PropertyDeniedDN         = PropertyPrefix + "DeniedDN"
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

		if strings.HasPrefix(key, PropertyPrefix) {
			prop, err := parseAttributeValue(key, obj)
			if err != nil {
				return nil, ParseError(fmt.Errorf("failed to get property on %s: %w", dn, err))
			}

			switch key {
			case PropertyBindPasswordAttr:
				object.bindPasswords = prop.Values()
			case PropertyAllowedDN:
				fallthrough
			case PropertyDeniedDN:
				for _, dn := range prop.Values() {
					object.acls = append(object.acls, objectAclRule{dn, key == PropertyAllowedDN})
				}
			default:
				return nil, ParseError(fmt.Errorf("unkown property %s on %s", strings.TrimPrefix(key, PropertyPrefix), dn))
			}
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
	sort.Sort(object.acls)
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
