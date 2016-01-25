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

func (r *AccountStoreRealm) SetName(name string) {
    r.name = name
}

func (r *AccountStoreRealm) SetAccountStore(store authc.AccountStore) {
    r.accountStore = store
}

func (r *AccountStoreRealm) SetCredentialsMatcher(matcher credential.CredentialsMatcher) {
    r.credentialsMatcher = matcher
}


func (r *AccountStoreRealm) Supports(token authc.AuthenticationToken) bool {
    _,ok := token.(authc.UsernamePasswordToken)
    
    return ok
}

// For Authenticator
func (r *AccountStoreRealm) Authenticate(token authc.AuthenticationToken) (authc.Account,error) {
    acc, err := r.accountStore.GetAccountByToken(token)
    
    if acc != nil {
        if ok := r.credentialsMatcher.CredentialsMatch(token, acc); !ok {
            return nil, new(authc.IncorrectCredentialsError)
        }
    } 
    
    return acc,err
}