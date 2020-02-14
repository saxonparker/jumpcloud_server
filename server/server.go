package server

import (
	"context"
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

// Helper struct for passing requests from the POST handler to the hash worker. Includes the password to hash, the id
// of that password, and the time to hash it.
type passwordRequest struct {
	Password   string
	ID         uint64
	TimeToHash time.Time
}

func newPasswordRequest(password string, id uint64, delay time.Duration) *passwordRequest {
	p := &passwordRequest{password, id, time.Now().Add(delay)}
	return p
}

// HashServer is an HTTP server for hashing passwords. It provides the following endpoints
//  - /hash - POST a new password to hash
//  - /hash/<id> - GET a hashed password
//  - /stats - GET stats on hashed passwords
//  - /shutdown - Shuts down the server
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
	shutdown bool
	// This RWLock is locked as a reader by all normal request handlers, and held as a writer by the shutdown
	// request handler. It is done this way to prevent a shutdown from occurring while a POST request is outstanding.
	// The shutdown handler will close the hashRequests channel, so if a POST handler tried to write after that,
	// the program would crash. Using an RWLock like this prevents the shutdown from being able to close the channel
	// while POSTs are outstanding.
	shutdownRW sync.RWMutex

	// HTTP Server
	server    http.Server
	serverMux *http.ServeMux

	// Channels for signalling completion
	workerDone   chan struct{}
	shutdownDone chan struct{}
}

// NewHashServer creates a new HashServer with the following args:
//  - port: The port to listen on
//  - hashDelay: How long to delay hashing a password
//  - chanSize: The size of the channel of outstanding hash requests. This limits the number of outstanding requests
func NewHashServer(port uint, hashDelay time.Duration, chanSize uint64) *HashServer {
	p := new(HashServer)
	p.port = port
	p.hashDelay = hashDelay
	p.count = 0
	p.avgUsec = 0
	p.hashRequests = make(chan *passwordRequest, chanSize)
	p.hashedPasswords = make(map[uint64]string)
	p.shutdown = false
	p.serverMux = http.NewServeMux()
	p.server = http.Server{Addr: fmt.Sprintf(":%d", p.port), Handler: p.serverMux}
	p.workerDone = make(chan struct{})
	p.shutdownDone = make(chan struct{})
	return p
}

// The hashWorker function is meant to be run as a goroutine. It receives password requests on the hashRequests channel
// and performs the hash at the right time.
func (hs *HashServer) hashWorker() {
	hasher := sha512.New()

	// Process requests until the hashRequests channel is closed (by a shutdown requests)
	// and there are no more requests to hash.
	for req := range hs.hashRequests {
		// Sleep until it's actually time to hash the password. The sleep method will return immediately
		// if the provided Duration is negative, so there's no need to check if TimeToHash is in the past.
		time.Sleep(req.TimeToHash.Sub(time.Now()))

		// Perform the hash
		hasher.Reset()
		hasher.Write([]byte(req.Password))
		hashed := hasher.Sum(nil)
		base := base64.StdEncoding.EncodeToString(hashed)

		// Update the map
		hs.hashedMux.Lock()
		hs.hashedPasswords[req.ID] = base
		hs.hashedMux.Unlock()
	}

	close(hs.workerDone)
}

// Handler for /hash/<ID>
func (hs *HashServer) hashGetHandler(w http.ResponseWriter, r *http.Request) {
	// Grab the read lock so we don't shut down while performing this operation
	hs.shutdownRW.RLock()
	defer hs.shutdownRW.RUnlock()

	if hs.shutdown {
		http.Error(w, "Server shut down", http.StatusMethodNotAllowed)
	}

	switch r.Method {
	case "GET":
		// Parse the requested ID
		reqID := r.URL.Path[len("/hash/"):]
		id, err := strconv.ParseUint(reqID, 0, 64)
		if err != nil {
			http.Error(w, fmt.Sprintf("Expected request id to be an integer, but got '%s'\n", reqID), http.StatusBadRequest)
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

// Handler for POST requests to /hash
func (hs *HashServer) hashPostHandler(w http.ResponseWriter, r *http.Request) {
	// Grab the read lock so we don't shut down while performing the POST
	hs.shutdownRW.RLock()
	defer hs.shutdownRW.RUnlock()

	if hs.shutdown {
		http.Error(w, "Server shut down", http.StatusMethodNotAllowed)
	}

	switch r.Method {
	case "POST":
		timeStart := time.Now()

		// Parse the request
		if err := r.ParseForm(); err != nil {
			http.Error(w, fmt.Sprintf("Could not parse request. Error: %v\n", err), http.StatusBadRequest)
			return
		}

		password := r.FormValue("password")
		if password == "" {
			http.Error(w, fmt.Sprintf("'password' not provided in form. Nothing to hash."), http.StatusBadRequest)
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
	// Grab the read lock so we don't shut down while performing this operation
	hs.shutdownRW.RLock()
	defer hs.shutdownRW.RUnlock()

	if hs.shutdown {
		http.Error(w, "Server shut down", http.StatusMethodNotAllowed)
	}

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

// Handles requests to the /shutdown endpoint
func (hs *HashServer) shutdownHandler(w http.ResponseWriter, r *http.Request) {
	// Grab the write lock here. Because we're going to close the request channel, we have to be sure that there
	// are no POST requests currently going, otherwise a POST request could write to a closed channel, which would
	// panic.
	hs.shutdownRW.Lock()
	defer hs.shutdownRW.Unlock()

	// Only the first call to shutdown should close the channel
	if !hs.shutdown {
		hs.shutdown = true

		// Close the channel to the hash worker, so it knows to stop when it's processed all outstanding requests
		close(hs.hashRequests)

		// Shut down the HTTP server
		go func() {
			hs.server.Shutdown(context.Background())
			close(hs.shutdownDone)
		}()
	}
}

// Run runs the HashServer. It will block until a request is made to /shutdown
func (hs *HashServer) Run() {

	// Start up hash worker
	go hs.hashWorker()

	// Add handlers
	hs.serverMux.HandleFunc("/hash", hs.hashPostHandler)
	hs.serverMux.HandleFunc("/hash/", hs.hashGetHandler)
	hs.serverMux.HandleFunc("/stats", hs.statsHandler)
	hs.serverMux.HandleFunc("/shutdown", hs.shutdownHandler)

	// Launch the server
	go func() {
		if err := hs.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Wait for all work to complete before exiting
	<-hs.shutdownDone
	<-hs.workerDone
}
