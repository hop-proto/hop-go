// Package agent defines the Hop Agent server and API.
package agent

import (
	"encoding/json"
	"net/http"

	"goji.io"
	"goji.io/pat"
)

// Server is an http.Handler that serves the Hop Agent endpoints.
type Server struct {
	*goji.Mux
	d *Data
}

// New creates a Server.
func New(d *Data) Server {
	s := Server{
		Mux: goji.NewMux(),
		d:   d,
	}
	s.Handle(pat.Get("/keys"), http.HandlerFunc(s.listKeys))
	s.Handle(pat.Post("/exchange"), http.HandlerFunc(s.exchange))
	return s
}

// KeyListResponse is the JSON structure returned by GET /keys.
type KeyListResponse struct {
	Keys []KeyDescription `json:"keys"`
}

// KeyDescription is a JSON structure describing a single key.
type KeyDescription struct {
	KeyID   string `json:"key_id"`
	Type    string `json:"type,omitempty"`
	Public  []byte `json:"public"`
	Version int    `json:"version,omitempty"`
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	out := KeyListResponse{
		Keys: []KeyDescription{}, // non-null empty list
	}
	for p, k := range s.d.Keys {
		out.Keys = append(out.Keys, KeyDescription{
			KeyID:   p,
			Type:    "DH",
			Public:  k.Public[:],
			Version: 1,
		})
	}
	enc := json.NewEncoder(w)
	err := enc.Encode(&out)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
	}
}

// ExchangeRequest is JSON structure defining the input to an (EC)DH operation
// for POST /exchange.
type ExchangeRequest struct {
	KeyID string `json:"key_id"`
	Other []byte `json:"other"`
}

// ExchangeResponse is a JSON structure defining the output of POST /exchange.
type ExchangeResponse struct {
	KeyID        string `json:"key_id"`
	SharedSecret []byte `json:"shared_secret"`
}

func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	var req ExchangeRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	k, ok := s.d.Keys[req.KeyID]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	sharedSecret, err := k.DH(req.Other)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	out := ExchangeResponse{
		KeyID:        req.KeyID,
		SharedSecret: sharedSecret,
	}
	err = json.NewEncoder(w).Encode(&out)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
}
