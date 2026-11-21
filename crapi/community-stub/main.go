// crapi-community stub — replaces the upstream empty binary.
// Provides just enough HTTP surface for crapi-web's Nginx proxy to start
// and health-check correctly, and returns minimal valid JSON for all
// community endpoints so crapi-workshop's dependency on community resolves.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func jsonOK(w http.ResponseWriter, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
}

func main() {
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8087"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("healthy"))
	})

	// Community posts list + create
	mux.HandleFunc("/community/api/v2/community/posts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			jsonOK(w, map[string]interface{}{
				"posts":    []interface{}{},
				"next_url": nil,
				"prev_url": nil,
			})
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			jsonOK(w, map[string]interface{}{
				"id":    "stub-00000000-0000-0000-0000-000000000001",
				"title": "stub post",
			})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// Individual post lookup (BOLA target — any user can read any ID)
	mux.HandleFunc("/community/api/v2/community/posts/", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]interface{}{
			"id":      "stub-00000000-0000-0000-0000-000000000001",
			"title":   "stub community post",
			"content": "stub",
			"author":  map[string]string{"nickname": "stub-user"},
		})
	})

	// Coupon validation
	mux.HandleFunc("/community/api/v2/coupon/", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]interface{}{
			"coupon_code": "STUB30",
			"amount":      "0",
		})
	})

	// Catch-all
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]interface{}{"status": "ok"})
	})

	log.Printf("crapi-community stub listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
