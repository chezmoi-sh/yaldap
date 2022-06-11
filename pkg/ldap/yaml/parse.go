package yaml

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	yaldaplib "github.com/xunleii/yaldap/pkg/ldap"
)

const (
	// attributePrefix prefixes LDAP attributes.
	attributePrefix = ".@"
	// propertyPrefix prefixes all internal yaLDAP properties that used internally.
	propertyPrefix           = ".#"
	propertyBindPasswordAttr = propertyPrefix + "BindPasswordAttr"
	propertyAllowedDN        = propertyPrefix + "AllowedDN"
	propertyDeniedDN         = propertyPrefix + "DeniedDN"
)

// ParseError describes a failure occurring during the parsing of the YAML definition.
type ParseError error

func parseObject(dn string, obj map[string]interface{}, index map[string]*object) (*object, error) {
	object := &object{
		dn:         dn,
		children:   map[string]*object{},
		attributes: yaldaplib.Attributes{},
	}
	index[dn] = object

	for key, obj := range obj {
		if strings.HasPrefix(key, attributePrefix) {
			key = strings.TrimPrefix(key, attributePrefix)
			values, err := parseAttributeValue(key, obj)
			if err != nil {
				return nil, ParseError(fmt.Errorf("failed to get attribute on %s: %w", dn, err))
			}
			object.attributes[key] = values
			continue
		}

		if strings.HasPrefix(key, propertyPrefix) {
			prop, err := parseAttributeValue(key, obj)
			if err != nil {
				return nil, ParseError(fmt.Errorf("failed to get property on %s: %w", dn, err))
			}

			switch key {
			case propertyBindPasswordAttr:
				object.bindPasswords = prop.Values()
			case propertyAllowedDN:
				fallthrough
			case propertyDeniedDN:
				for _, dn := range prop.Values() {
					object.acls = append(object.acls, objectAclRule{dn, key == propertyAllowedDN})
				}
			default:
				return nil, ParseError(fmt.Errorf("unkown property %s on %s", strings.TrimPrefix(key, propertyPrefix), dn))
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

		object.children[key].attributes[sp[0]] = &attribute{sp[1]}
	}
	sort.Sort(object.acls)
	return object, nil
}

func parseAttributeValue(key string, obj interface{}) (*attribute, error) {
	switch value := obj.(type) {
	case []string:
		return (*attribute)(&value), nil

	case []interface{}:
		var values attribute

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
		return &attribute{value}, nil
	case int:
		return &attribute{strconv.Itoa(value)}, nil
	case bool:
		return &attribute{strconv.FormatBool(value)}, nil

	default:
		return nil, ParseError(fmt.Errorf("invalid attribute type '%T' on attribute '%s'", value, key))
	}
}
