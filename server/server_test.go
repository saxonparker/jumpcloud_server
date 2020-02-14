package server

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	{"jumpcloud",
		"7+jtE9tp16UQHMShH1l0uMlq1JFX3lg0NisRl0iipoR7Fr2APaYLDFS+vxE0B4VR4l3aM2+1lh6uESYP/SCLGw=="},
	{"saxonparker",
		"THNwi3OdsADA2XXrvxvGjrgbqudj5qck7OqxQBO/H0iXlYdcSyLV23r+gcjWTdFPMk0VkHMeTLQtqp4/7FFdGQ=="},
}

func TestServer(t *testing.T) {
	serv := NewHashServer(8080, 0, 500)
	done := make(chan struct{})
	go func() {
		serv.Run()
		close(done)
	}()

	for i, val := range testValues {
		// Generate POST request
		data := url.Values{}
		data.Add("password", val.Password)
		post, _ := http.NewRequest("POST", "/hash", bytes.NewBufferString(data.Encode()))
		post.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		postRes := httptest.NewRecorder()
		serv.hashPostHandler(postRes, post)

		if postRes.Body.String() != strconv.Itoa(i+1) {
			t.Errorf("Unexpected return value: %s", postRes.Body)
		}

		// Now get the result
		// Sleep a bit to make sure the server had time to perform the hash
		time.Sleep(time.Millisecond * 10)
		get, _ := http.NewRequest("GET", fmt.Sprintf("/hash/%d", i+1), nil)
		getRes := httptest.NewRecorder()
		serv.hashGetHandler(getRes, get)

		if getRes.Body.String() != val.Hashed {
			t.Errorf("Unexpected hashed string for password %s. Expected %s, Got %s", val.Password, val.Hashed, getRes.Body.String())
		}
	}

	// Check stats
	stat, _ := http.NewRequest("GET", "/stats", nil)
	statRes := httptest.NewRecorder()
	serv.statsHandler(statRes, stat)
	var st stats
	err := json.Unmarshal(statRes.Body.Bytes(), &st)
	if err != nil {
		t.Errorf("Could not parse stats json. Err: %v", err)
	}
	if st.Total != uint64(len(testValues)) {
		t.Errorf("Unexpected total stat: %d", st.Total)
	}
	// We won't know what the average time is, just check for an absurd value
	if st.Average > 1000 {
		t.Errorf("Stats average time too high: %d", st.Average)
	}

	// Test shutdown
	down, _ := http.NewRequest("GET", "/shutdown", nil)
	downRes := httptest.NewRecorder()
	serv.shutdownHandler(downRes, down)
	<-done
}
