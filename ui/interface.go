package ui

import (
	"net/http"
)

type Vampire interface {
	OnNewRequest(req *http.Request)
	FilterRequest(regex string) []*http.Request
}
