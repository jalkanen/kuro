package realm

import (
	"errors"
	"github.com/jalkanen/kuro/authc"
	"github.com/jalkanen/kuro/authc/credential"
	"github.com/jalkanen/kuro/authz"
	"github.com/jalkanen/kuro/ini"
	"io"
	"strings"
	"fmt"
)

type Realm interface {
	AuthenticationInfo(authc.AuthenticationToken) (authc.AuthenticationInfo,error)
	Name() string
	Supports(authc.AuthenticationToken) bool
}

type AuthenticatingRealm interface {
	Realm
	CredentialsMatcher() credential.CredentialsMatcher
}

type AuthorizingRealm interface {
	AuthenticatingRealm
	authz.Authorizer
}

// Reads the contents from an .ini file
type IniRealm struct {
	name               string
	users              map[string]authc.SimpleAccount
	roles              map[string]authz.SimpleRole
	credentialsMatcher credential.CredentialsMatcher
}

// Creates a new IniRealm, reading from a Reader.
func NewIni(name string, in io.Reader) (*IniRealm, error) {
	realm := IniRealm{name: name}
	realm.users = make(map[string]authc.SimpleAccount)
	realm.roles = make(map[string]authz.SimpleRole)

	ini, err := ini.Load(in)

	if err != nil {
		return nil, err
	}

	// Users
	for username, val := range ini.Section("users") {
		vals := strings.Split(val, ",")

		if len(vals) == 0 {
			return nil, errors.New("Invalid property in the INI file; assumed at least a password for user " + username)
		}

		// User account
		acct := authc.NewAccount(stringer(username), strings.TrimSpace(vals[0]), name)

		for _, role := range vals[1:] {
			acct.AddRole(strings.TrimSpace(role))
		}

		realm.users[username] = *acct
	}

	// Roles
	for role, permlist := range ini.Section("roles") {
		perms := strings.Split(permlist, ",")

		if len(perms) == 0 {
			return nil, errors.New("Role does not have any permissions")
		}

		r := authz.NewRole(role)

		for _, p := range perms {
			perm, err := authz.NewWildcardPermission(p)

			if err != nil {
				return nil, err
			}
			r.AddPermission(perm)
		}

		realm.roles[role] = *r
	}

	return &realm, nil
}

func (r *IniRealm) Name() string {
	return r.name
}

// Supports only UsernamePasswordTokens
func (r *IniRealm) Supports(token authc.AuthenticationToken) bool {
	_, ok := token.(*authc.UsernamePasswordToken)

	return ok
}

func (r *IniRealm) AuthenticationInfo(token authc.AuthenticationToken) (authc.AuthenticationInfo, error) {
	t,_ := token.(*authc.UsernamePasswordToken)

	acct, ok := r.users[t.Username()]

	if !ok {
		return nil, errors.New("No such user")
	}

	return &acct,nil
}

// AuthenticatingRealm interface

func (r *IniRealm) CredentialsMatcher() credential.CredentialsMatcher {
	return r.credentialsMatcher
}

// Authorizer interface

func (r *IniRealm) HasRole(principals []interface{}, role string) bool {
	if len(principals) == 0 {
		return false
	}

	acct, ok := r.users[principals[0].(stringer).String()]

	return ok && acct.HasRole(role)
}

func (r *IniRealm) IsPermittedP(principals []interface{}, permission authz.Permission) bool {
	acct, ok := r.users[principals[0].(stringer).String()]

	if ok {
		for _,role := range acct.Roles() {
			simplerole, gotit := r.roles[role]

			if gotit && simplerole.IsPermitted(permission) {
				return true
			}
		}
	}
	return false
}

func (r *IniRealm) IsPermitted(subjectPrincipal []interface{}, permission string) bool {
	p, err := authz.NewWildcardPermission(permission)

	if err != nil {
		return false;
	}

	return r.IsPermittedP(subjectPrincipal, p)
}

// Stringer interface

func (r *IniRealm) String() string {
	return fmt.Sprintf("IniRealm: %d users, %d roles", len(r.users), len(r.roles))
}

// A simple workaround of the fact that string is not a Stringer
type stringer string

func (s stringer) String() string { return string(s) }
