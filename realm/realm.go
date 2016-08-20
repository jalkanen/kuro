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
	"encoding/gob"
)

var (
	ErrUnknownAccount error = errors.New("Unknown account")
)

// Realms are essentially user, role and permission databases.
type Realm interface {
	AuthenticationInfo(authc.AuthenticationToken) (authc.AuthenticationInfo,error)
	Name() string
	Supports(authc.AuthenticationToken) bool
}

// An AuthenticatingRealm provides authentication capabilities
type AuthenticatingRealm interface {
	Realm
	CredentialsMatcher() credential.CredentialsMatcher
}

// An AuthorizingRealm provides authorization capabilities.  The Realm should provide a way
// to get the AuthorizationInfo.
type AuthorizingRealm interface {
	AuthenticatingRealm
	AuthorizationInfo(principals []interface{}) (authz.AuthorizationInfo,error)
}

// A simple in-memory realm. Highly performant, but does not reload its contents, so
// cannot be changed.  Useful for testing.  This is an AuthorizingRealm.
type SimpleAccountRealm struct {
	name               string
	users              map[string]authc.SimpleAccount
	roles              map[string]authz.SimpleRole
	credentialsMatcher credential.CredentialsMatcher
}

// Reads the contents from an .ini file; otherwise this is just a basic SimpleAccountRealm
type IniRealm struct {
	SimpleAccountRealm
}

func init() {
	var s stringer
	gob.Register(s)
}

// Creates a new IniRealm, reading from a Reader.
func NewIni(name string, in io.Reader) (*IniRealm, error) {
	realm := IniRealm{ SimpleAccountRealm{name: name} }
	realm.users = make(map[string]authc.SimpleAccount)
	realm.roles = make(map[string]authz.SimpleRole)
	realm.credentialsMatcher = &credential.PlainText{}

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

func (r *SimpleAccountRealm) Name() string {
	return r.name
}

// Supports only UsernamePasswordTokens
func (r *SimpleAccountRealm) Supports(token authc.AuthenticationToken) bool {
	_, ok := token.(*authc.UsernamePasswordToken)

	return ok
}

func (r *SimpleAccountRealm) AuthenticationInfo(token authc.AuthenticationToken) (authc.AuthenticationInfo, error) {
	t,_ := token.(*authc.UsernamePasswordToken)

	acct, ok := r.users[t.Username()]

	if !ok {
		return nil, ErrUnknownAccount
	}

	return &acct,nil
}

// AuthenticatingRealm interface

func (r *SimpleAccountRealm) CredentialsMatcher() credential.CredentialsMatcher {
	return r.credentialsMatcher
}

// AuthorizingRealm interface

func (r *SimpleAccountRealm) AuthorizationInfo(principals []interface{}) (authz.AuthorizationInfo, error) {

	if len(principals) == 0 {
		return nil,errors.New("No principals")
	}

	if acct, ok := r.users[fmt.Sprint(principals[0])]; ok {
		return &acct, nil
	}

	return nil,ErrUnknownAccount
}

// Authorizer interface

func (r *SimpleAccountRealm) HasRole(principals []interface{}, role string) bool {
	if len(principals) == 0 {
		return false
	}

	acct, ok := r.users[fmt.Sprint(principals[0])]

	return ok && acct.HasRole(role)
}

func (r *SimpleAccountRealm) IsPermittedP(principals []interface{}, permission authz.Permission) bool {
	acct, err := r.AuthorizationInfo(principals)

	if err != nil {
		for _,role := range acct.Roles() {
			simplerole, gotit := r.roles[role]

			if gotit && simplerole.IsPermitted(permission) {
				return true
			}
		}
	}
	return false
}

func (r *SimpleAccountRealm) IsPermitted(subjectPrincipal []interface{}, permission string) bool {
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
