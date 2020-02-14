# Jumpcloud Interview Assignment
## Author: Saxon Parker

## Implementation
My HTTP server is based on Golang's 'net/http' library. The main workflow for hashing passwords is as follows:

```
________________                             ______________                           _______________ 
| Post Handler | ---> Buffered Channel ---> | Hash Worker | ---> map[int]string  ---> | Get Handler |
|______________|                            |_____________|                           |_____________|
```

### Post Handler
 * Parses request
 * Assigns an ID to the requested password. This ID is monotonically increasing
 * Determines how long in the future the password should be hashed.
 * Places the password to hash on the buffered channel. A buffered channel is used so that the maximum number of outstanding request can be limited. Otherwise, you could theoretically OOM the server by blasting it with enough requests during the 5 second delay.

### Hash Worker
The hash worker is a goroutine responsible for actually hashing passwords. It does so via the following steps:
 * Receives a hash request from the channel
 * Sleeps until it is time to hash the password.
 * Hashes the password
 * Places it in the map of ID -> Hashed Password to be read by the Get Handler

### Get Handler
 * Parses request to get ID of password to return
 * Looks up ID in the map of hashed passwords and returns the hashed password, if it exists

My server also implements the '/stats' and '/shutdown' endpoints.

## Build and Run
The code can be built with `go build`. This will produce the executable `jumpcloud_server`. The server provides the following command line options:

```
Usage of ./jumpcloud_server:
  -delay uint
        Time (in seconds) to delay before hashing a password (default 5)
  -port uint
        The port for the server to listen on (default 8080)
  -qsize uint
        Size of the queue of passwords waiting to be hashed. If this queue becomes full, new requests will block until pending requests are hashed. (default 500)
```
Unit tests can be run by `cd server/ && go test`. There is currently only one unit test. With more time, I'd certainly like to add more unit tests, as well as integration tests that launch a server and perform HTTP requests. I did manual testing of a running server with various `curl` commands.

The code was built and run with `go version go1.13.8 linux/amd64`
