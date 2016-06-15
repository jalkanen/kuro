/*
	Authorization-related packages.
*/
package authz

import (
	"bytes"
	"errors"
	"strings"
	"sort"
	"fmt"
)

const (
	WildcardSeparator    = ":"
	WildcardSubSeparator = ","
	WildcardToken        = "*"
)


//  A Permission represents a permission granted to a principal.
//  The Implies() method checks if this permission implies the given permission, in other
//  words - is the owner of this permission allowed to perform an action described by the
//  other permission.
//
//  A Permission must implement String() as per the fmt.Stringer.
//
//  Permissions are immutable, reusable and thread-safe.
type Permission interface {
	Implies(permission Permission) bool
	fmt.Stringer // One must implement "String()"
}

/*
	AllPermission always returns true on Implies(), and therefore is usable really only
	for system or admin users.  Because this permission really allows you to do everything.
*/
type AllPermission struct {
}

func (p AllPermission) Implies(permission Permission) bool {
	return true
}

func (p AllPermission) String() string {
	return "*"
}

/*
	A WildcardPermission provides a simple structure for permissions.  Each
	permission has multiple colon-separated parts, some of which can be wildcards (*).

	For example, a permission can be a simple string "write" for really simple cases.
	However, a more complicated permission might be "printers:write", or even "printers:hp:print",
	consisting of three parts.  You could also separate multiple permissions, e.g.
	"printers:hp:print,manage".

	For example, you could grant an user a permission "printers:*:print", which would then mean
	that the user would be allowed to print on any printer, regardless of the manufacturer. The printer
	code would check if the user is allowed to do "printers:hp:print" before proceeding, and the
	wildcard would match.  However, if the user attempted to perform management for the printer,
	the permission "printers:hp:manage" wouldn't be allowed under the "printers:*:print" -permission
	granted previously to the user.

	The permissions must not contain whitespaces.
 */
type WildcardPermission struct {
	parts []map[string]bool
}

/*
	Create a new WildcardPermission based on the string representation.  Each permission
	must be one or more parts, separated by colons, containing subpermissions separated
	with commas.
 */
func NewWildcardPermission(parts string) (*WildcardPermission, error) {
	p := new(WildcardPermission)

	err := p.setParts(parts)

	if err != nil {
		return nil, err
	}

	return p, nil
}

// Implements the Permission interface.  The incoming permission MUST be
// another WildcardPermission.
func (w *WildcardPermission) Implies(permission Permission) bool {
	otherPermission, ok := permission.(*WildcardPermission)
	if !ok {
		return false
	}

	otherParts := otherPermission.parts

	i := 0

	for i < len(otherParts) {
		otherPart := otherParts[i]
		// if this permission has less parts than the other permission,
		// everything after this point is automatically implied
		if len(w.parts)-1 < i {
			return true
		} else {
			part := w.parts[i]
			if !part[WildcardToken] && !containsAll(part, otherPart) {
				return false
			}
		}
		i++
	}

	// If this permission has more parts than the other, only imply it if all the other parts are wildcards
	for i < len(w.parts) {
		part := w.parts[i]
		if !part[WildcardToken] {
			return false
		}
		i++
	}

	return true
}

// Return true, if this contains all the elements in that (may contain more)
func containsAll(this map[string]bool, that map[string]bool) bool {
	for key, _ := range that {
		if !this[key] {
			return false
		}
	}

	return true
}

// Parse the bits and pieces of the wildcard permission string
func (w *WildcardPermission) setParts(partsString string) error {
	parts := strings.TrimSpace(partsString)

	if parts == "" {
		return errors.New("parts must not be an empty string")
	}

	partsArray := strings.Split(parts, WildcardSeparator)

	w.parts = make([]map[string]bool, len(partsArray))

	for index, part := range partsArray {
		subStr := strings.TrimSpace(part)
		subArr := strings.Split(subStr, WildcardSubSeparator)

		w.parts[index] = make(map[string]bool)

		for _, sub := range subArr {
			if sub != "" {
				w.parts[index][strings.ToLower(sub)] = true
			}
		}

		//  ",,,"
		if len(w.parts[index]) == 0 {
			return errors.New("Wildcard string cannot contain parts with only dividers.")
		}
	}

	// ":::"
	if len(w.parts) == 0 {
		return errors.New("Wildcard string cannot contain only dividers.")
	}

	return nil
}

// Returns a canonical representation of this Permission.  All the subcomponents
// will be sorted in alphabetical order.
func (w WildcardPermission) String() string {
	var buf bytes.Buffer

	for idx, p := range w.parts {
		if idx > 0 {
			buf.WriteString(WildcardSeparator)
		}

		keys := make([]string, 0, len(p))

		for key, _ := range p {
			keys = append(keys,key)
		}

		sort.Strings(keys)
		subcount := 0

		for _,key := range keys {
			if subcount > 0 {
				buf.WriteString(WildcardSubSeparator)
			}
			buf.WriteString(key)
			subcount = subcount + 1
		}
	}

	return buf.String()
}
