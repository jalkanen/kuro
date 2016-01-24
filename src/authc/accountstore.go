package authc

import (
)

type AccountStore interface {
    GetAccountByToken( AuthenticationToken ) (Account,error)
    GetAccountById( AccountId ) (Account,error)
}