// Loopback WebSocket echo server (coder/websocket, the library whatsmeow uses) for crypto/ref/ws.c.
// Echoes binary messages; counts unsolicited pong frames (the WhatsA500 heartbeat) and answers the
// binary message "pongs?" with "pongs:<count>" instead of an echo.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/coder/websocket"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:4434", "address")
	flag.Parse()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		panic(err)
	}
	fmt.Println("READY", ln.Addr().String())
	done := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pongs int32
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"},
			OnPongReceived: func(ctx context.Context, payload []byte) { atomic.AddInt32(&pongs, 1) }})
		if err != nil {
			fmt.Println("ACCEPT ERROR:", err)
			return
		}
		ctx := context.Background()
		c.SetReadLimit(1 << 21)
		for i := 0; ; i++ {
			typ, data, err := c.Read(ctx)
			if err != nil {
				fmt.Println("READ END:", err)
				break
			}
			if typ != websocket.MessageBinary {
				c.Close(websocket.StatusUnsupportedData, "binary only")
				break
			}
			reply := append([]byte("echo:"), data...)
			if string(data) == "pongs?" {
				reply = []byte(fmt.Sprintf("pongs:%d", atomic.LoadInt32(&pongs)))
				fmt.Println("PONGS", atomic.LoadInt32(&pongs))
			}
			if err := c.Write(ctx, websocket.MessageBinary, reply); err != nil {
				break
			}
		}
		c.Close(websocket.StatusNormalClosure, "bye")
		close(done)
	})}
	go srv.Serve(ln)
	<-done
	fmt.Println("CLOSED")
}
