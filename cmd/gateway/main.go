package main

import (
	"log"
	"net"
	"net/http"
	"os"

	"telemetry-gateway/internal/gateway"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	tcpAddr := ":" + env("TCP_PORT", "9000")
	httpAddr := ":" + env("HTTP_PORT", "8080")

	srv := gateway.NewServer()

	ln, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		log.Fatalf("listen tcp %s: %v", tcpAddr, err)
	}
	go func() {
		if err := srv.ServeTCP(ln); err != nil {
			log.Fatalf("tcp server: %v", err)
		}
	}()
	log.Printf("telemetry gateway up: tcp=%s http=%s", tcpAddr, httpAddr)
	log.Fatal(http.ListenAndServe(httpAddr, srv.HTTPHandler()))
}
