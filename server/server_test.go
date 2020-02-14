package server

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

type testValue struct {
	Password string
	Hashed   string
}

var testValues = [...]testValue{
	{"angryMonkey",
		"ZEHhWB65gUlzdVwtDQArEyx+KVLzp/aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A+gf7Q=="},
}

func TestHashing(t *testing.T) {
	serv := NewHashServer(8080, 0, 500)
	go func() {
		serv.hashWorker()
	}()

	for i, val := range testValues {
		// Generate POST request
		data := url.Values{}
		data.Add("password", val.Password)
		post, _ := http.NewRequest("POST", "/hash", bytes.NewBufferString(data.Encode()))
		post.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		postRes := httptest.NewRecorder()
		serv.hashPostHandler(postRes, post)

		resp := postRes.Result()
		body, _ := ioutil.ReadAll(resp.Body)
		if string(body) != strconv.Itoa(i+1) {
			t.Errorf("Unexpected return value: %s", string(body))
		}

		// Now get the result
		// Sleep a bit to make sure the server had time to perform the hash
		time.Sleep(time.Millisecond * 10)
		get, _ := http.NewRequest("GET", fmt.Sprintf("/hash/%d", i+1), nil)
		getRes := httptest.NewRecorder()
		serv.hashGetHandler(getRes, get)

		resp = getRes.Result()
		body, _ = ioutil.ReadAll(resp.Body)
		if string(body) != val.Hashed {
			t.Errorf("Unexpected hashed string: %s", string(body))
		}
	}
}
