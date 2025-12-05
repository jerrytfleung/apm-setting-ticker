package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	bearerPrefix    = "Bearer "
	bearerPrefixLen = len(bearerPrefix)

	// 2 hours
	corsMaxAge = 60 * 60 * 2

	headerAllow            = "Allow"
	headerAuthorization    = "Authorization"
	headerContentType      = "Content-Type"
	headerCorsAllowHeaders = "Access-Control-Allow-Headers"
	headerCorsAllowMethods = "Access-Control-Allow-Methods"
	headerCorsAllowOrigin  = "Access-Control-Allow-Origin"
	headerCorsMaxAge       = "Access-Control-Max-Age"

	mimeJson = "application/json"
)

// GlobalData is a package-level map acting as a global dictionary.
// Using a sync.Mutex to protect concurrent access.
var GlobalData = struct {
	sync.RWMutex
	data map[string][]byte
}{
	data: make(map[string][]byte),
}

func getSHA256Hash(data string) string {
	// Create a new SHA256 hasher
	hasher := sha256.New()

	// Write the string data (converted to bytes) to the hasher
	hasher.Write([]byte(data))

	// Get the finalized hash as a byte slice and encode it to a hexadecimal string
	return hex.EncodeToString(hasher.Sum(nil))
}

//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>

// handler is a function that handles incoming HTTP requests.
// It takes an http.ResponseWriter to write the response and an
// *http.Request to read the request details.
func handler(w http.ResponseWriter, r *http.Request) {
	methods := strings.Join([]string{http.MethodGet, http.MethodOptions}, ", ")
	w.Header().Add(headerAllow, methods)
	w.Header().Add(headerCorsAllowMethods, methods)

	w.Header().Add(headerCorsAllowOrigin, "*")
	w.Header().Add(headerCorsAllowHeaders, headerAuthorization)
	w.Header().Add(headerCorsMaxAge, strconv.Itoa(corsMaxAge))

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		break
	case http.MethodOptions:
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var token string
	service := r.PathValue("service")
	hostname := r.PathValue("hostname")

	auth := r.Header.Get(headerAuthorization)
	if len(auth) >= bearerPrefixLen && auth[:bearerPrefixLen] == bearerPrefix {
		token = auth[bearerPrefixLen:]
	}

	GlobalData.RLock()
	val := GlobalData.data[getSHA256Hash(token+":"+service+hostname)]
	GlobalData.RUnlock()
	w.Header().Add(headerContentType, mimeJson)
	_, _ = w.Write(val)
}

func request(logger *zap.Logger, collector string, serviceKey string, hostname string) {
	serviceName := "unknown"
	keyArr := strings.Split(serviceKey, ":")
	if len(keyArr) == 2 {
		serviceName = keyArr[1]
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequest("GET", "https://"+collector+"/v1/settings/"+serviceName+"/"+hostname, nil)
	if err != nil {
		logger.Error("unable to create request", zap.Error(err))
	}
	if req == nil {
		logger.Error("request is nil")
		return
	}
	req.Header.Add("Authorization", "Bearer "+keyArr[0])
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("request failed", zap.Error(err))
	}
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			logger.Error("failed to close response body", zap.Error(closeErr))
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("failed to read response body", zap.Error(err))
	}

	GlobalData.Lock()
	GlobalData.data[getSHA256Hash(serviceKey+hostname)] = body
	GlobalData.Unlock()
}

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	serviceKey, found := os.LookupEnv("SW_APM_SERVICE_KEY")
	if !found {
		logger.Fatal("SW_APM_SERVICE_KEY environment variable is not set")
	}
	hostname, found := os.LookupEnv("HOSTNAME")
	if !found {
		logger.Fatal("HOSTNAME environment variable is not set")
	}
	collector, found := os.LookupEnv("SW_APM_COLLECTOR")
	if !found {
		collector = "apm.collector.na-01.cloud.solarwinds.com"
	}
	port, found := os.LookupEnv("PORT")
	if !found {
		port = "8080"
	}

	server := &http.Server{Addr: ":" + port}

	http.HandleFunc("/v1/settings/{service}/{hostname}", handler)

	// Create a channel to listen for OS signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(60 * time.Second)

	done := make(chan bool)

	// Initial request before starting the ticker
	request(logger, collector, serviceKey, hostname)

	// Launch a goroutine to handle the ticker events.
	go func() {
		for {
			select {
			case <-done:
				// If the 'done' channel receives a signal, exit the goroutine.
				return
			case <-ticker.C:
				// On each tick, perform request.
				request(logger, collector, serviceKey, hostname)
			}
		}
	}()

	// Start the HTTP server in a goroutine
	go func() {
		logger.Info("HTTP server started on :8080")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("HTTP server failed", zap.Error(err))
		}
	}()

	// Block until a signal is received
	<-quit

	ticker.Stop()

	// Signal the goroutine to exit.
	close(done) // Closing a channel sends a zero value to all receivers.

	// Create a context with a timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() // Release resources associated with the context

	// Attempt to gracefully shut down the server
	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("HTTP server shutdown failed", zap.Error(err))
	}

	logger.Info("HTTP server stopped gracefully.")
}
