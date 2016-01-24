package authc

import (
    
)

type Account interface {
    Id() AccountId
    Credentials() interface{}
    Attributes() map[string]interface{}
}

type AccountId interface {
    toString() string
}