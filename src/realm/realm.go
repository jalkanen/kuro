package realm

import (
    "authc"
    "authz"
    "authc/credential"
)

type Realm interface {
    authz.Authorizer
    Name() string
    Supports(authc.AuthenticationToken) bool
}

type AccountStoreRealm struct {
    name string
    accountStore authc.AccountStore
    credentialsMatcher credential.CredentialsMatcher
}

func (r *AccountStoreRealm) Name() string {
    return r.name
}

func (r *AccountStoreRealm) supports(token authc.AuthenticationToken) bool {
    _,ok := token.(authc.UsernamePasswordToken)
    
    return ok
}

// For Authenticator
func (r *AccountStoreRealm) authenticate(token authc.AuthenticationToken) (authc.Account,error) {
    acc, err := r.accountStore.GetAccountByToken(token)
    
    if acc != nil {
        
    } 
    
    return acc,err
}