package yaml

import (
	"testing"

	"github.com/jimlambrt/gldap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectoryEntry_Search(t *testing.T) {
	yaml := `
l1:a:
  .@attr1: true
  .@attr2: true
  l2:a:
    .@attr1: true
    .@attr2: false
    l3:a:
      .@attr2: false
    l3:b:
      .@attr1: true
      .@attr2: false
      .@uniq: yes
  l2:b:
    .@attr2: true
  l2:c:
    .@attr1: false
    .@attr2: true
    l3:a:
      l4:a:
        .@attr1: true
        .@attr2: false
`
	directory, _ := NewDirectory([]byte(yaml))
	object := directory.BaseDN("l1=a")

	tests := []struct {
		name     string
		scope    gldap.Scope
		filter   string
		expected []string
	}{
		{name: "ExistsOnBaseObject",
			scope:    gldap.BaseObject,
			filter:   "(attr1=*)",
			expected: []string{"l1=a"}},
		{name: "ExistsOnSingleLevel",
			scope:    gldap.SingleLevel,
			filter:   "(attr1=*)",
			expected: []string{"l1=a", "l2=a,l1=a", "l2=c,l1=a"}},
		{name: "ExistsOnWholeSubtree",
			scope:    gldap.WholeSubtree,
			filter:   "(attr1=*)",
			expected: []string{"l1=a", "l2=a,l1=a", "l3=b,l2=a,l1=a", "l2=c,l1=a", "l4=a,l3=a,l2=c,l1=a"}},
		{name: "NotExistsOrAttr2IsFalseOnBaseObject",
			scope:    gldap.BaseObject,
			filter:   "(|(!attr1=*)(attr2=false))",
			expected: []string{}},
		{name: "NotExistsOrAttr2IsFalseOnSingleLevel",
			scope:    gldap.SingleLevel,
			filter:   "(|(!attr1=*)(attr2=false))",
			expected: []string{"l2=b,l1=a", "l2=a,l1=a"}},
		{name: "NotExistsOrAttr2IsFalseOnWholeSubtree",
			scope:    gldap.WholeSubtree,
			filter:   "(|(!attr1=*)(attr2=false))",
			expected: []string{"l2=a,l1=a", "l3=a,l2=a,l1=a", "l3=b,l2=a,l1=a", "l2=b,l1=a", "l3=a,l2=c,l1=a", "l4=a,l3=a,l2=c,l1=a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs, err := object.Search(tt.scope, tt.filter)
			require.NoError(t, err)

			var dns []string
			for _, obj := range objs {
				dns = append(dns, obj.DN())
			}

			assert.ElementsMatch(t, tt.expected, dns)
		})
	}
}

func TestObject_Nil_Search(t *testing.T) {
	objs, err := (*Object)(nil).Search(gldap.BaseObject, "")
	assert.Empty(t, objs)
	assert.NoError(t, err)
}
