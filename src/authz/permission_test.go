package authz

import (
    "testing"
)

func TestAllPermission(t *testing.T) {
    v := AllPermission{}
    v2 := AllPermission{}
    if !v.implies(v2) || !v2.implies(v) {
        t.Fatalf("AllPermission does not return true always")
    }
}

func TestWildcardPermissionEmpty(t *testing.T) {
    _, err := NewWildcardPermission("")
    
    if err == nil {
        t.Fatalf("Empty permission not rejected")
    }
}

func TestWildcardPermissionSpaces(t *testing.T) {
    _, err := NewWildcardPermission("               ")
    
    if err == nil {
        t.Fatalf("Empty permission not rejected")
    }
}

func TestWildcardPermissionSimple(t *testing.T) {
    p1,_ := NewWildcardPermission("something")
    p2,_ := NewWildcardPermission("something")
    
    if !p1.implies(p2) || !p2.implies(p1) {
        t.Error()
    }
}
 
func TestWildcardPermissionImplies(t *testing.T) {
    pall,_ := NewWildcardPermission("*")
    p1,_ := NewWildcardPermission("bar")
    p2all,_ := NewWildcardPermission("bar:*")
    p2,_ := NewWildcardPermission("bar:2")
    ap := new(AllPermission)
    
    if pall.implies( ap ) {
        t.Errorf("Problem: %s implies %s", pall, ap)                
    }

    if !pall.implies(p1) {
        t.Errorf("Problem: %s does not imply %s", pall, p1)        
    }

    if !p2all.implies(p2) {
        t.Errorf("Problem: %s does not imply %s", p2all, p2)        
    }

    if !pall.implies(p2) {
        t.Errorf("Problem: %s does not imply %s", pall, p2)        
    }

    if p2.implies(p1) {
        t.Errorf("Problem: %s implies %s", p2, p1)        
    }

    if !p1.implies(p2) {
        t.Errorf("Problem: %s does not imply %s", p1, p2)        
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

