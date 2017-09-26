package ui

import (
	"net/http"
)

// Vampire this interface should be implemented if you want to interact with the events that are fired by the proxy
// All methods are called synchronously, that being said: should your implementation block the execution, you must run it inside of a goroutine
type Vampire interface {
	// OnIncomingRequest is called when a request is received from the client (which is using the proxy )
	OnIncomingRequest(reqDump []byte, req *http.Request)
	// OnOutgoingRequest is called when a request is about to be sent to the target server
	OnOutgoingRequest(reqDump []byte, req *http.Request)
	// OnIncomingResponse is called whenever a target server has responded to out request
	OnIncomingResponse(resDump []byte, res *http.Response)
}

type NoOpVampire struct {
}

func (vamp *NoOpVampire) OnIncomingRequest(reqDump []byte, req *http.Request) {

}

func (vamp *NoOpVampire) OnOutgoingRequest(reqDump []byte, req *http.Request) {

}

func (vamp *NoOpVampire) OnIncomingResponse(resDump []byte, res *http.Response) {

}
