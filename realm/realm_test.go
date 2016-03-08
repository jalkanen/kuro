package realm

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"strings"
	"github.com/jalkanen/kuro/authc"
)

func TestIni(t *testing.T) {
	src := `
  # Start with a comment

  something = other

  [users]
  foo = password
  bar = password2, admin,     agroup,manager
  baz=pwd

  [roles]

  admin = *
  agroup= read:*
  manager = write:*, manage:*
`

	ini,err := NewIni("test-ini", strings.NewReader(src))

	assert.Nil(t, err, "Got an error: %s", err)

	assert.Equal(t, "test-ini",ini.Name())

	token := authc.NewToken("foo", "password")

	assert.True(t, ini.Supports(token), "Does not support UsernamePasswordTokens!")

	var acct authc.AuthenticationInfo

	acct, err = ini.AuthenticationInfo(token)

	assert.Nil(t, err, "Got an error:", err)

	assert.NotNil(t, acct)


}
