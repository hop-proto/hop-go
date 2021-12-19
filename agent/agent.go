package agent

import (
	"encoding/json"
	"net/http"

	"goji.io"
	"goji.io/pat"
)

type Server struct {
	*goji.Mux
	d *Data
}

func New(d *Data) Server {
	s := Server{
		Mux: goji.NewMux(),
		d:   d,
	}
	s.Handle(pat.Get("/keys"), http.HandlerFunc(s.listKeys))
	return s
}

type KeyListResponse struct {
	Keys []KeyDescription `json:"keys"`
}

type KeyDescription struct {
	ID      string `json:"id"`
	Type    string `json:"type,omitempty"`
	Version int    `json:"version,omitempty"`
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	out := KeyListResponse{
		Keys: []KeyDescription{}, // non-null empty list
	}
	for p := range s.d.Keys {
		out.Keys = append(out.Keys, KeyDescription{
			ID:      p,
			Type:    "DH",
			Version: 1,
		})
	}
	enc := json.NewEncoder(w)
	err := enc.Encode(&out)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
	}
}
