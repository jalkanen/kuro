package kuro_test

import (
	"log"
	"net/http"
	"github.com/jalkanen/kuro"
)

// Displays how to get the Subject in an HTTP context.
func Example_getSubject() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		subject := kuro.Get(r, w)

		log.Printf("Is Subject authenticated? %s\n", subject.IsAuthenticated())
	})
	log.Fatal(http.ListenAndServe(";6999", nil))
}