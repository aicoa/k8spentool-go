package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trymonoly/K8sPenTool-ng/internal/api"
	"github.com/trymonoly/K8sPenTool-ng/internal/api/ws"
)

func main() {
	var (
		port    = flag.Int("port", 8080, "Server port")
		host    = flag.String("host", "0.0.0.0", "Server host")
		mode    = flag.String("mode", "server", "Run mode: server")
		version = flag.Bool("version", false, "Show version")
	)
	flag.Parse()

	if *version {
		fmt.Println("K8sPenTool-ng v2.0.0")
		return
	}

	switch *mode {
	case "server":
		runServer(*host, *port)
	default:
		fmt.Printf("Unknown mode: %s\n", *mode)
		flag.Usage()
		os.Exit(1)
	}
}

func runServer(host string, port int) {
	hub := ws.NewHub()
	go hub.Run()

	router := api.SetupRouter(hub)

	addr := fmt.Sprintf("%s:%d", host, port)
	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	go func() {
		log.Printf("[K8sPenTool-ng] Server starting on %s", addr)
		log.Printf("[K8sPenTool-ng] OpenAPI spec: http://%s/openapi.json", addr)
		log.Printf("[K8sPenTool-ng] WebSocket: ws://%s/api/v1/ws", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Listen error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[K8sPenTool-ng] Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Shutdown error: %v", err)
	}
	log.Println("[K8sPenTool-ng] Server stopped")
}
