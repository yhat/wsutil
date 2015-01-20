package wsutil

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func EchoWSHandler(ws *websocket.Conn) {
	io.Copy(ws, ws)
}

// Helper function to send an WS request to a given path. urlStr is assumed to
// be the url from a httptest.Server
func SendWSRequest(urlStr, data string, t *testing.T) (string, error) {
	if data == "" {
		return "", fmt.Errorf("cannot send no data to a websocket")
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	u.Scheme = "ws"
	origin := "http://localhost/"
	errc := make(chan error)
	wsc := make(chan *websocket.Conn)
	go func() {
		ws, err := websocket.Dial(u.String(), "", origin)
		if err != nil {
			errc <- err
			return
		}
		wsc <- ws
	}()
	var ws *websocket.Conn
	select {
	case err := <-errc:
		return "", err
	case ws = <-wsc:
	case <-time.After(time.Second * 2):
		return "", fmt.Errorf("websocket dial timed out")
	}
	defer ws.Close()
	msgc := make(chan string)
	go func() {
		if _, err := ws.Write([]byte(data)); err != nil {
			errc <- err
			return
		}
		var msg = make([]byte, 512)
		var n int
		if n, err = ws.Read(msg); err != nil {
			errc <- err
			return
		}
		msgc <- string(msg[:n])
	}()
	select {
	case err := <-errc:
		return "", err
	case msg := <-msgc:
		t.Logf("response from ws: '%s'", msg)
		return msg, nil
	case <-time.After(time.Second * 2):
		return "", fmt.Errorf("websocket request timed out")
	}
}

func TestWebSocketProxy(t *testing.T) {
	go func() {
		time.Sleep(5 * time.Second)
		panic("hi")
	}()
	echoServer := http.NewServeMux()
	echoServer.Handle("/echo/ws", websocket.Handler(EchoWSHandler))
	// make sure that the proxy preserves url queries
	queryAssert := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("foo") != "bar" {
			t.Errorf("request is missing url query")
		}
		echoServer.ServeHTTP(w, r)
	})
	backend := httptest.NewServer(queryAssert)
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	backendURL.Path = "/echo"
	proxy := httptest.NewServer(NewSingleHostReverseProxy(backendURL))
	defer proxy.Close()

	for _, data := range []string{"eric is so cool", "some data", "else"} {
		resp, err := SendWSRequest(proxy.URL+"/ws?foo=bar", data, t)
		if err != nil {
			t.Error(err)
			continue
		}
		if resp != data {
			t.Errorf("expected '%s' from server, got '%s'", data, resp)
		}
	}
}

func TestReverseProxy(t *testing.T) {
	h := http.NewServeMux()
	h.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		ws.Write([]byte("wssuccess"))
		ws.Close()
	}))
	h.HandleFunc("/http", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("httpsuccess"))
	})
	isWSHandler := func(w http.ResponseWriter, r *http.Request) {
		isWS := IsWebSocketRequest(r)
		if isWS && (r.URL.Path != "/ws") {
			t.Errorf("detected ws and got path %s", r.URL.Path)
		} else if !isWS && (r.URL.Path != "/http") {
			t.Errorf("detected http and got path %s", r.URL.Path)
		}
		h.ServeHTTP(w, r)
	}
	n := httptest.NewServer(http.HandlerFunc(isWSHandler))
	defer n.Close()
	errc := make(chan error)
	go func() {
		resp, err := http.Get(n.URL + "/http")
		if err != nil {
			errc <- fmt.Errorf("could not GET url: %v", err)
			return
		}
		defer resp.Body.Close()
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			errc <- fmt.Errorf("could not read from body")
			return
		}
		t.Logf("response from http request: %s", data)
		if string(data) != "httpsuccess" {
			errc <- fmt.Errorf("expected 'httpsuccess' got '%s'", string(data))
			return
		}
		errc <- nil
	}()
	select {
	case err := <-errc:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(4 * time.Second):
		t.Error("http request timed out")
	}
	go func() {
		t.Logf("making request to server")
		wsResp, err := SendWSRequest(n.URL+"/ws", "a lot of data", t)
		if err != nil {
			errc <- fmt.Errorf("could not connect to ws server: %v", err)
			return
		}
		t.Logf("got response from server: %s", wsResp)
		if wsResp != "wssuccess" {
			errc <- fmt.Errorf("expected 'wssuccess' got '%s'", wsResp)
			return
		}
		errc <- nil
	}()
	t.Logf("waiting for response from websocket")
	select {
	case err := <-errc:
		if err != nil {
			t.Error(err)
		}
		return
	case <-time.After(4 * time.Second):
		t.Error("websocket request timed out")
		return
	}
}
