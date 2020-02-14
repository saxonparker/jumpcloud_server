package main

import (
	"flag"
	"time"

	"github.com/saxonparker/jumpcloud_server/server"
)

func main() {
	port := flag.Uint("port", 8080, "The port for the server to listen on")
	delay := flag.Uint("delay", 5, "Time (in seconds) to delay before hashing a password")
	qsize := flag.Uint64("qsize", 500, "Size of the queue of passwords waiting to be hashed. If this queue becomes full, new requests will block until pending requests are hashed.")

	flag.Parse()

	hs := server.NewHashServer(*port, time.Second*time.Duration(*delay), *qsize)
	hs.Run()
}
