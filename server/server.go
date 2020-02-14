package server

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type passwordRequest struct {
	Password   string
	ID         uint64
	TimeToHash time.Time
}

func newPasswordRequest(password string, id uint64, delay time.Duration) *passwordRequest {
	p := &passwordRequest{password, id, time.Now().Add(delay)}
	return p
}

type HashServer struct {
	// Port to listen on
	port uint

	// Amount of time to delay hashing a password
	hashDelay time.Duration

	// Tracks the number of requests that have been made thus far
	count uint64
	// Tracks the average time of POST requests
	avgUsec int64
	// Both count and avgUsec are protected by this lock. Each value could have its own lock, but this makes it
	// easier for the stats endpoint to grab one lock and get both fields.
	countMux sync.Mutex

	// Channel to send passwords to worker to be hashed
	hashRequests chan *passwordRequest

	// Map
	hashedPasswords map[uint64]string
	hashedMux       sync.Mutex

	// Shutdown bool to indicate if the server has been shutdown
	shutdown    bool
	shutdownMux sync.Mutex
}

func NewHashServer(port uint, hashDelay time.Duration, chanSize uint64) *HashServer {
	p := new(HashServer)
	p.port = port
	p.hashDelay = hashDelay
	p.count = 0
	p.avgUsec = 0
	p.hashRequests = make(chan *passwordRequest, chanSize)
	p.hashedPasswords = make(map[uint64]string)
	p.shutdown = false
	return p
}

func (hs *HashServer) hashWorker() {
	hasher := sha512.New()

	// Process requests until the hashRequests channel is closed (by a shutdown requests)
	// and there are no more requests to hash.
	for req := range hs.hashRequests {
		// Sleep until it's actually time to hash the password. The sleep method will return immediately
		// if the provided Duration is negative, so there's no need to check if TimeToHash is in the past.
		time.Sleep(req.TimeToHash.Sub(time.Now()))

		// Perform the hash
		hasher.Write([]byte(req.Password))
		hashed := hasher.Sum(nil)
		base := base64.URLEncoding.EncodeToString(hashed)

		// Update the map
		hs.hashedMux.Lock()
		hs.hashedPasswords[req.ID] = base
		hs.hashedMux.Unlock()
	}
}

func (hs *HashServer) hashGetHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Parse the requested ID
		reqID := r.URL.Path[len("/hash/"):]
		id, err := strconv.ParseUint(reqID, 0, 64)
		if err != nil {
			fmt.Fprintf(w, "Expected request id to be an integer, but got '%s'\n", reqID)
			return
		}

		hs.hashedMux.Lock()
		password := hs.hashedPasswords[id]
		hs.hashedMux.Unlock()

		// If the id wasn't in the map, this response will be empty.
		// You could possibly return an error in that case, but that doesn't really seem like an error condition.
		fmt.Fprintf(w, "%s", password)
	// Only GET requests allowed
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (hs *HashServer) hashPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		timeStart := time.Now()

		// Parse the request
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "Could not parse request. Error: %v\n", err)
			return
		}
		password := r.FormValue("password")
		if password == "" {
			fmt.Fprintf(w, "'password' not provided in form. Nothing to hash.")
			return
		}

		// Determine the id for this request
		hs.countMux.Lock()
		hs.count++
		id := hs.count
		hs.countMux.Unlock()

		// Pass the new request to worker to actually perform the request
		req := newPasswordRequest(password, id, hs.hashDelay)
		hs.hashRequests <- req
		fmt.Fprintf(w, "%d", id)

		// Calculate the elapsed time and update the average
		timeEnd := time.Now()
		elapsed := int64(timeEnd.Sub(timeStart) / time.Microsecond)
		hs.countMux.Lock()
		// Moving average calculation taken from https://stackoverflow.com/a/37830174
		hs.avgUsec = hs.avgUsec + (elapsed-hs.avgUsec)/int64(id)
		hs.countMux.Unlock()

	// Only POST requests allowed
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

// Helper struct for marshalling the stats JSON
type stats struct {
	Total   uint64 `json:"total"`
	Average int64  `json:"average"`
}

// Handles requests to the /stats endpoint
func (hs *HashServer) statsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Gather the fields under the lock. We'll do the JSON marshalling outside the lock
		hs.countMux.Lock()
		total := hs.count
		avg := hs.avgUsec
		hs.countMux.Unlock()

		stat := stats{total, avg}
		b, err := json.Marshal(stat)

		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to marshal stats. Err: %v", err), http.StatusInternalServerError)
		}

		w.Write(b)

	// Only GET requests allowed
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (hs *HashServer) Run() {
	go hs.hashWorker()
	http.HandleFunc("/hash", hs.hashPostHandler)
	http.HandleFunc("/hash/", hs.hashGetHandler)
	http.HandleFunc("/stats", hs.statsHandler)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", hs.port), nil))
}
