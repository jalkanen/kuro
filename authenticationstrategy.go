package kuro

import (
	"github.com/jalkanen/kuro/realm"
	"github.com/jalkanen/kuro/authc"
	"errors"
	"fmt"
)

/*
	An AuthenticationStrategy is used when you have multiple different Realms and you wish to control what happens if
	some of the Realms work and some don't.

	If an error is returned from any of these methods, the processing stops and the authentication is considered failed.
 */
type AuthenticationStrategy interface {
	BeforeAllAttempts(realms []realm.Realm, token authc.AuthenticationToken) (authc.AuthenticationInfo,error)
	AfterAllAttempts(token authc.AuthenticationToken, aggregate authc.AuthenticationInfo) (authc.AuthenticationInfo, error)
	BeforeAttempt(realm realm.Realm, token authc.AuthenticationToken, aggregateInfo authc.AuthenticationInfo) (authc.AuthenticationInfo, error)
	AfterAttempt(realm realm.Realm, token authc.AuthenticationToken, singleRealmInfo authc.AuthenticationInfo, aggregateInfo authc.AuthenticationInfo, errorFromAuthenticate error) (authc.AuthenticationInfo, error)
}

// AbstractAuthenticationStrategy provides sane default implementations for the different methods.
type AbstractAuthenticationStrategy struct {}

func (s *AbstractAuthenticationStrategy) BeforeAllAttempts(realms []realm.Realm, token authc.AuthenticationToken) (authc.AuthenticationInfo,error) {
	return &authc.SimpleAccount{}, nil
}

func (s *AbstractAuthenticationStrategy) AfterAllAttempts(token authc.AuthenticationToken, aggregate authc.AuthenticationInfo) (authc.AuthenticationInfo, error) {
	return aggregate, nil
}

func (s *AbstractAuthenticationStrategy) BeforeAttempt(realm realm.Realm, token authc.AuthenticationToken, aggregate authc.AuthenticationInfo) (authc.AuthenticationInfo, error) {
	return aggregate, nil
}

// Just merges the contents of the singleRealmInfo into the aggregate
func (s *AbstractAuthenticationStrategy) AfterAttempt(realm realm.Realm, token authc.AuthenticationToken, singleRealmInfo authc.AuthenticationInfo, aggregate authc.AuthenticationInfo, errorFromAuthenticate error) (authc.AuthenticationInfo, error) {
	if singleRealmInfo == nil {
		return aggregate, nil
	}

	if aggregate == nil {
		return singleRealmInfo, nil
	}

	if errorFromAuthenticate != nil {
		return aggregate, errorFromAuthenticate
	}

	if info, ok := aggregate.(authc.MergableAuthenticationInfo); ok {
		info.Merge(singleRealmInfo)

		return aggregate, nil
	}

	return singleRealmInfo, errors.New("Aggregate is not a MergableAuthenticationInfo, so cannot merge the contents. Just returning the singleRealmInfo.")
}

/***********************************************************************************************************

	AllSuccessFullStrategy is a strategy that assumes that all realms must support the given token
	and that every single realm must succeed for authentication to be successful.

 ***********************************************************************************************************/

type AllSuccessfulStrategy struct {
	AbstractAuthenticationStrategy
}

func (s *AllSuccessfulStrategy) BeforeAttempt(realm realm.Realm, token authc.AuthenticationToken, aggregate authc.AuthenticationInfo) (authc.AuthenticationInfo, error) {
	if !realm.Supports(token) {
		return aggregate, errors.New(fmt.Sprintf("Realm %s does not support this type of authenticationtoken.  It is necessary for AllSuccessfulStrategy to work properly.", realm.Name()))
	}

	return aggregate, nil
}

// Just merges the contents of the singleRealmInfo into the aggregate
func (s *AllSuccessfulStrategy) AfterAttempt(realm realm.Realm, token authc.AuthenticationToken, singleRealmInfo authc.AuthenticationInfo, aggregate authc.AuthenticationInfo, errorFromAuthenticate error) (authc.AuthenticationInfo, error) {
	if errorFromAuthenticate != nil {
		return aggregate, errorFromAuthenticate
	}

	if singleRealmInfo == nil {
		return aggregate, errors.New(fmt.Sprintf("Realm %s did not provide useful authentication info, does account exist?", realm.Name()))
	}

	if info, ok := aggregate.(authc.MergableAuthenticationInfo); ok {
		info.Merge(singleRealmInfo)
		return aggregate, nil
	}

	return singleRealmInfo, errors.New("Aggregate is not a MergableAuthenticationInfo, so cannot merge the contents. Just returning the singleRealmInfo.")
}

/***********************************************************************************************************

	AtLeastOneSuccessfulStrategy is a strategy that succeeds if at least one of the realms succeeded.

 ***********************************************************************************************************/

type AtLeastOneSuccessfulStrategy struct {
	AbstractAuthenticationStrategy
}

func (s *AtLeastOneSuccessfulStrategy) AfterAllAttempts(token authc.AuthenticationToken, aggregate authc.AuthenticationInfo) (authc.AuthenticationInfo, error) {
	if aggregate == nil || len(aggregate.Principals()) == 0 {
		return nil, errors.New("None of the configured realms were able to log in using this authentication token.")
	}

	return aggregate, nil
}


