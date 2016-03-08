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

/*
 */
type Permission interface {
	Implies(permission Permission) bool
	fmt.Stringer // One must implement "String()"
}

/*
	AllPermission always returns true on the implies().
*/
type AllPermission struct {
}

func (p AllPermission) Implies(permission Permission) bool {
	return true
}

func (p AllPermission) String() string {
	return "*"
}

type WildcardPermission struct {
	parts []map[string]bool
}

func NewWildcardPermission(parts string) (*WildcardPermission, error) {
	p := new(WildcardPermission)

	err := p.setParts(parts)

	if err != nil {
		return nil, err
	}

	return p, nil
}

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
