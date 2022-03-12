// Package agent defines the Hop Agent server and API.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"goji.io"
	"goji.io/pat"

	"zmap.io/portal/keys"
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
	s.Handle(pat.Get("/keys/:keyid"), http.HandlerFunc(s.getKey))
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
		return
	}
}

func (s *Server) getKey(w http.ResponseWriter, r *http.Request) {
	keyID := pat.Param(r, "keyid")
	k, ok := s.d.Keys[keyID]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	out := KeyDescription{
		KeyID:   keyID,
		Type:    "DH",
		Public:  k.Public[:],
		Version: 1,
	}
	enc := json.NewEncoder(w)
	err := enc.Encode(&out)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
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

// Client speaks to the agent Server and can create keys.Exchanger
// implementations.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Get fetches the description of a single key by ID.
func (c *Client) Get(ctx context.Context, keyID string) (*KeyDescription, error) {
	u := fmt.Sprintf("%s/%s", c.BaseURL, url.PathEscape(keyID))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	desc := KeyDescription{}
	if err := json.NewDecoder(res.Body).Decode(&desc); err != nil {
		return nil, err
	}
	return &desc, nil
}

// Exchange calls the /exchange endpoint
func (c *Client) Exchange(ctx context.Context, request *ExchangeRequest) (*ExchangeResponse, error) {
	u := fmt.Sprintf("%s/exchange", c.BaseURL)
	buf := bytes.Buffer{}
	if err := json.NewEncoder(&buf).Encode(request); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", u, &buf)
	if err != nil {
		return nil, err
	}
	out := ExchangeResponse{}
	if err := json.NewDecoder(req.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

type boundClient struct {
	c      *Client
	ctx    context.Context
	keyID  string
	public []byte
}

var _ keys.Exchangable = &boundClient{}

func (bc *boundClient) Share() []byte {
	return bc.public
}

func (bc *boundClient) Agree(other []byte) ([]byte, error) {
	request := ExchangeRequest{
		KeyID: bc.keyID,
		Other: other,
	}
	resp, err := bc.c.Exchange(bc.ctx, &request)
	if err != nil {
		return nil, err
	}
	return resp.SharedSecret, nil
}

// ExchangerFor returns an implementation of keys.Exchangable that is bound to
// the provided keyID and implemented using the Exchange endpoint on the server.
// The public key will be retrieved and cached at the time of creation.
func (c *Client) ExchangerFor(ctx context.Context, keyID string) (keys.Exchangable, error) {
	bc := boundClient{c: c, keyID: keyID}
	desc, err := c.Get(ctx, keyID)
	if err != nil {
		return nil, err
	}
	bc.public = desc.Public
	return &bc, nil
}
