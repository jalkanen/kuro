package http

import (
	"net/http"
)

// Your subject etc should implement these
type HTTPAware interface {
	Request()  *http.Request
	Response() http.ResponseWriter
}


