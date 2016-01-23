package authz

import (
    "testing"
)

func TestAllPermission(t *testing.T) {
    v := AllPermission{}
    v2 := AllPermission{}
    if !v.implies(v2) {
        t.Fatalf("AllPermission does not return true always")
    }
}

func TestWildcardPermissionFaulty(t *testing.T) {
    _, err := NewWildcardPermission("")
    
    if err == nil {
        t.Fatalf("Empty permission not rejected")
    }
}


func TestWildcardPermissionParsing(t *testing.T) {
    p, err := NewWildcardPermission("foo:BAR:1,2,3")

    if err != nil {
        t.Fatalf("Parsing no worky")        
    }

    if len(p.parts[0]) != 1 {
        t.Fatalf("Parsing no worky 1")
    }    

    if len(p.parts[1]) != 1 {
        t.Fatalf("Parsing no worky 2")
    }    
    
    if len(p.parts[2]) != 3 {
        t.Fatalf("Parsing no worky 3")
    }    

    if !p.parts[0]["foo"] {
        t.Fatalf("Subparsing no worky 1")        
    }

    if !p.parts[1]["bar"] {
        t.Fatalf("Subparsing no worky 2")        
    }

    if !p.parts[2]["1"] || !p.parts[2]["2"] || !p.parts[2]["3"] {
        t.Fatalf("Subparsing no worky 3")        
    }

}

