/*
	Authorization-related packages.
*/
package authz

import (
    "strings"
    "errors"
    "bytes"
)

const (
    WildcardSeparator = ":"
    WildcardSubSeparator = ","
)

/*
 */
type Permission interface {
	implies(permission Permission) bool
}

/*
	AllPermission always returns true on the implies().
 */
type AllPermission struct {
}

func (p AllPermission) implies(permission Permission) bool {
    return true
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

// Parse the bits and pieces of the wildcard permission string
func (w *WildcardPermission) setParts(partsString string) error {
    
    if partsString == "" {
        return errors.New("parts must not be an empty string")
    }
    
    parts := strings.TrimSpace(partsString)
    
    partsArray := strings.Split(parts, WildcardSeparator)
    
    w.parts = make( []map[string]bool, len(partsArray) )
    
    for index,part := range partsArray {
        subStr := strings.TrimSpace(part)
        subArr := strings.Split(subStr, WildcardSubSeparator)
        
        w.parts[index] = make( map[string]bool )
        
        for _,sub := range subArr {
            w.parts[index][strings.ToLower(sub)] = true
        }
    } 
    
    return nil
}

func (w WildcardPermission) String() string {
    var buf bytes.Buffer
    
    for idx,p := range w.parts {
        if idx > 0 {
            buf.WriteString( WildcardSeparator )
        }
        
        subcount := 0
        for key,_ := range p {
            if( subcount > 0 ) {
                buf.WriteString( WildcardSubSeparator )
            }
            buf.WriteString(key)
            subcount = subcount + 1
        }
    }
    
    return buf.String()
} 