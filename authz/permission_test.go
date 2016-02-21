package authz

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestAllPermission(t *testing.T) {
	v := AllPermission{}
	v2 := AllPermission{}

	assert.True(t, v.implies(v2))
	assert.True(t, v2.implies(v))
}

func TestWildcardPermissionEmpty(t *testing.T) {
	_, err := NewWildcardPermission("")

	assert.NotNil(t, err)
}

func TestWildcardPermissionSpaces(t *testing.T) {
	_, err := NewWildcardPermission("               ")

	assert.NotNil(t,err)

	_, err = NewWildcardPermission("    :      :     ")

	assert.NotNil(t,err)

}

func TestWildcardPermissionSeparators(t *testing.T) {
	p, err := NewWildcardPermission("::,,::,:")

	assert.NotNil(t,err, "Got %+v", p)
}

func TestWildcardPermissionSeparatorsCommas(t *testing.T) {
	p, err := NewWildcardPermission(",,,")

	assert.NotNil(t,err, "Got %+v", p)
}

func TestWildcardPermissionSimple(t *testing.T) {
	p1, _ := NewWildcardPermission("something")
	p2, _ := NewWildcardPermission("something")

	assert.True(t, p1.implies(p2))
	assert.True(t, p2.implies(p1))
}

func TestWildcardPermissionImplies(t *testing.T) {
	pall, _ := NewWildcardPermission("*")
	p1, _ := NewWildcardPermission("bar")
	p2all, _ := NewWildcardPermission("bar:*")
	p2, _ := NewWildcardPermission("bar:2")
	ap := new(AllPermission)

	assert.False(t, pall.implies(ap))

	assert.True(t, pall.implies(p1))

	assert.True(t, p2all.implies(p2))

	assert.True(t, pall.implies(p2))

	assert.False(t, p2.implies(p1))

	assert.True(t, p1.implies(p2))
}

func TestWildcardPermissionImplies2(t *testing.T) {
	p1, _ := NewWildcardPermission("foo:BAR:1,2,3")
	p2, _ := NewWildcardPermission("foo:BAR:3")
	p3, _ := NewWildcardPermission("foo:BAR:4")

	assert.True(t, p1.implies(p2))

	assert.False(t, p1.implies(p3))

}

func TestWildcardPermissionParsing(t *testing.T) {
	p, err := NewWildcardPermission("foo:BAR:1,2,3")

	assert.Nil(t, err)

	assert.Equal(t, 1, len(p.parts[0]))

	assert.Equal(t, 1, len(p.parts[1]))

	assert.Equal(t, 3, len(p.parts[2]))

	assert.True(t, p.parts[0]["foo"])

	assert.True(t, p.parts[1]["bar"])

	assert.True(t, p.parts[2]["1"] && p.parts[2]["2"] && p.parts[2]["3"] )

}

func TestWildcardPermissionString(t *testing.T) {
	p, err := NewWildcardPermission("foo:BAR:1,2")

	assert.Nil(t, err)

	s := p.String()
	assert.True(t, s == "foo:bar:1,2" || s == "foo:bar:2,1")
}


func TestNamed(t *testing.T) {
	var p1, p2 *WildcardPermission

	// Case insensitive, same
	p1,_ = NewWildcardPermission("something")
	p2,_ = NewWildcardPermission("something")
	assert.True(t, p1.implies(p2))
	assert.True(t, p2.implies(p1))

	// Case insensitive, different case
	p1,_ = NewWildcardPermission("something")
	p2,_ = NewWildcardPermission("SOMETHING")
	assert.True(t, p1.implies(p2))
	assert.True(t, p2.implies(p1))

	// Case insensitive, different word
	p1,_ = NewWildcardPermission("something")
	p2,_ = NewWildcardPermission("else")
	assert.False(t, p1.implies(p2))
	assert.False(t, p2.implies(p1))
/*
	// Case sensitive same
	p1 = NewWildcardPermission("BLAHBLAH", false)
	p2 = NewWildcardPermission("BLAHBLAH", false)
	assert.True(t, p1.implies(p2))
	assert.True(t, p2.implies(p1))

	// Case sensitive, different case
	p1 = NewWildcardPermission("BLAHBLAH", false)
	p2 = NewWildcardPermission("bLAHBLAH", false)
	assert.True(t, p1.implies(p2))
	assert.True(t, p2.implies(p1))

	// Case sensitive, different word
	p1 = NewWildcardPermission("BLAHBLAH", false)
	p2 = NewWildcardPermission("whatwhat", false)
	assert.False(t, p1.implies(p2))
	assert.False(t, p2.implies(p1))
	*/
}

func TestLists(t *testing.T) {
	var p1, p2, p3 *WildcardPermission

	p1,_ = NewWildcardPermission("one,two")
	p2,_ = NewWildcardPermission("one")
	assert.True(t,p1.implies(p2))
	assert.False(t,p2.implies(p1))

	p1,_ = NewWildcardPermission("one,two,three")
	p2,_ = NewWildcardPermission("one,three")
	assert.True(t,p1.implies(p2))
	assert.False(t,p2.implies(p1))

	p1,_ = NewWildcardPermission("one,two:one,two,three")
	p2,_ = NewWildcardPermission("one:three")
	p3,_ = NewWildcardPermission("one:two,three")
	assert.True(t,p1.implies(p2))
	assert.False(t,p2.implies(p1))
	assert.True(t,p1.implies(p3))
	assert.False(t,p2.implies(p3))
	assert.True(t,p3.implies(p2))

	p1,_ = NewWildcardPermission("one,two,three:one,two,three:one,two")
	p2,_ = NewWildcardPermission("one:three:two")
	assert.True(t,p1.implies(p2))
	assert.False(t,p2.implies(p1))

	p1,_ = NewWildcardPermission("one")
	p2,_ = NewWildcardPermission("one:two,three,four")
	p3,_ = NewWildcardPermission("one:two,three,four:five:six:seven")
	assert.True(t,p1.implies(p2))
	assert.True(t,p1.implies(p3))
	assert.False(t,p2.implies(p1))
	assert.False(t,p3.implies(p1))
	assert.True(t,p2.implies(p3))

}

func TestWildcards(t *testing.T) {
	var p1, p2, p3, p4, p5, p6, p7, p8 *WildcardPermission

	p1,_ = NewWildcardPermission("*")
	p2,_ = NewWildcardPermission("one")
	p3,_ = NewWildcardPermission("one:two")
	p4,_ = NewWildcardPermission("one,two:three,four")
	p5,_ = NewWildcardPermission("one,two:three,four,five:six:seven,eight")
	assert.True(t,p1.implies(p2))
	assert.True(t,p1.implies(p3))
	assert.True(t,p1.implies(p4))
	assert.True(t,p1.implies(p5))

	p1,_ = NewWildcardPermission("newsletter:*")
	p2,_ = NewWildcardPermission("newsletter:read")
	p3,_ = NewWildcardPermission("newsletter:read,write")
	p4,_ = NewWildcardPermission("newsletter:*")
	p5,_ = NewWildcardPermission("newsletter:*:*")
	p6,_ = NewWildcardPermission("newsletter:*:read")
	p7,_ = NewWildcardPermission("newsletter:write:*")
	p8,_ = NewWildcardPermission("newsletter:read,write:*")
	assert.True(t,p1.implies(p2))
	assert.True(t,p1.implies(p3))
	assert.True(t,p1.implies(p4))
	assert.True(t,p1.implies(p5))
	assert.True(t,p1.implies(p6))
	assert.True(t,p1.implies(p7))
	assert.True(t,p1.implies(p8))

	p1,_ = NewWildcardPermission("newsletter:*:*")
	assert.True(t,p1.implies(p2))
	assert.True(t,p1.implies(p3))
	assert.True(t,p1.implies(p4))
	assert.True(t,p1.implies(p5))
	assert.True(t,p1.implies(p6))
	assert.True(t,p1.implies(p7))
	assert.True(t,p1.implies(p8))

	p1,_ = NewWildcardPermission("newsletter:*:*:*")
	assert.True(t,p1.implies(p2))
	assert.True(t,p1.implies(p3))
	assert.True(t,p1.implies(p4))
	assert.True(t,p1.implies(p5))
	assert.True(t,p1.implies(p6))
	assert.True(t,p1.implies(p7))
	assert.True(t,p1.implies(p8))

	p1,_ = NewWildcardPermission("newsletter:*:read")
	p2,_ = NewWildcardPermission("newsletter:123:read")
	p3,_ = NewWildcardPermission("newsletter:123,456:read,write")
	p4,_ = NewWildcardPermission("newsletter:read")
	p5,_ = NewWildcardPermission("newsletter:read,write")
	p6,_ = NewWildcardPermission("newsletter:123:read:write")
	assert.True(t,p1.implies(p2))
	assert.False(t,p1.implies(p3))
	assert.False(t,p1.implies(p4))
	assert.False(t,p1.implies(p5))
	assert.True(t,p1.implies(p6))

	p1,_ = NewWildcardPermission("newsletter:*:read:*")
	assert.True(t,p1.implies(p2))
	assert.True(t,p1.implies(p6))

}