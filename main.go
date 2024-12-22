// eSCL test program

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const LogFileName = "escl-test.log"

var (
	// Logging
	LogFile    *os.File
	LogContext context.Context

	// HTTPClient is the normal http.Client
	HTTPClient = &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           DialContext,
			DialTLSContext:        DialTLSContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	// HTTPClientNoKeepAlives is the http.Client with disabled
	// HTTP keep-alive.
	HTTPClientNoKeepAlives = &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DialContext:       DialContext,
			DialTLSContext:    DialTLSContext,
			DisableKeepAlives: true,
		},
	}
)

// usage prints program usage page and exits.
func usage() {
	fmt.Printf("usage: %s scanner-url\n", os.Args[0])
	os.Exit(1)
}

// die prints error message and terminates the program.
func die(format string, args ...any) {
	log(format, args...)
	os.Exit(1)
}

// log prints a log message to console and the log file.
func log(format string, args ...any) {
	s := []byte(fmt.Sprintf(format+"\n", args...))
	os.Stdout.Write(s)
	if LogFile != nil {
		LogFile.Write(s)
	}
}

// logHTTPExchange logs a HTTP request/response exchange.
func logHTTPExchange(rq *http.Request, rsp *http.Response, err error) {
	if err != nil {
		log("%s %s -- %s", rq.Method, rq.URL, err)
	} else {
		log("%s %s -- %s", rq.Method, rq.URL, rsp.Status)
	}
}

// URLParse parses the eSCL scanner URL.
func URLParse(s string) (*url.URL, error) {
	u, err := url.Parse(s)

	if err != nil ||
		(u.Scheme != "http" && u.Scheme != "https") ||
		u.Host == "" {
		err = fmt.Errorf("%s: invalid URL", s)
		return nil, err
	}

	u.Path = path.Clean(u.Path)

	return u, nil
}

// URLMake makes a target URL, relative to the given base URL.
func URLMake(base *url.URL, rs string) *url.URL {
	u := &url.URL{}
	*u = *base
	u.Path = path.Clean(path.Join(u.Path, rs))
	return u
}

// DoScanJobs sends eSCL ScanJobs request and returns either
// the image download URL or an error.
func DoScanJobs(base *url.URL) (*url.URL, error) {
	log("DoScanJobs")

	const xml = `` +
		`<?xml version="1.0" encoding="UTF-8"?>` +
		`<scan:ScanSettings xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm" xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03">` +
		`<pwg:Version>2.0</pwg:Version>` +
		`<pwg:ScanRegions>` +
		`<pwg:ScanRegion>` +
		`<pwg:ContentRegionUnits>escl:ThreeHundredthsOfInches</pwg:ContentRegionUnits>` +
		`<pwg:XOffset>0</pwg:XOffset>` +
		`<pwg:YOffset>0</pwg:YOffset>` +
		`<pwg:Width>2550</pwg:Width>` +
		`<pwg:Height>3508</pwg:Height>` +
		`</pwg:ScanRegion>` +
		`</pwg:ScanRegions>` +
		`<pwg:InputSource>Feeder</pwg:InputSource>` +
		`<scan:ColorMode>Grayscale8</scan:ColorMode>` +
		`<pwg:DocumentFormat>image/jpeg</pwg:DocumentFormat>` +
		`<scan:DocumentFormatExt>image/jpeg</scan:DocumentFormatExt>` +
		`<scan:XResolution>300</scan:XResolution>` +
		`<scan:YResolution>300</scan:YResolution>` +
		`<scan:Duplex>false</scan:Duplex>` +
		`</scan:ScanSettings>`

	// Make HTTP request
	rq := &http.Request{
		Method:        "POST",
		URL:           URLMake(base, "ScanJobs"),
		Body:          io.NopCloser(strings.NewReader(xml)),
		ContentLength: int64(len(xml)),
		Header:        make(http.Header),
	}

	rq.Header.Set("Content-Type", "text/xml")
	rq.Header.Set("Connection", "keep-alive")

	rq = rq.WithContext(LogContext)

	// Send HTTP request and get the response
	rsp, err := HTTPClient.Do(rq)
	logHTTPExchange(rq, rsp, err)

	if err != nil {
		return nil, fmt.Errorf("ScanJobs: %s", err)
	}

	io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()

	// Analyze HTTP status code
	if rsp.StatusCode/100 != 2 {
		err := fmt.Errorf("ScanJobs: HTTP %s", rsp.Status)
		return nil, err
	}

	// Obtain image location
	location := rsp.Header.Get("Location")
	if location == "" {
		return nil, errors.New("ScanJobs: missed Location header")
	}

	log("Location: %s", location)

	// Parse returned location URL
	return URLParse(location)

}

// DoNextDocument sends eSCL NextDocument request.
// It returns the length of received image, HTTP status (0 if not available)
// and error, if any.
func DoNextDocument(img *url.URL) (int64, int, error) {
	log("DoNextDocument")

	// Make HTTP request
	rq := &http.Request{
		Method: "GET",
		URL:    URLMake(img, "NextDocument"),
		Header: make(http.Header),
	}

	rq.Header.Set("Connection", "keep-alive")
	rq = rq.WithContext(LogContext)

	// Send HTTP request and get the response
	rsp, err := HTTPClient.Do(rq)
	logHTTPExchange(rq, rsp, err)

	if err != nil {
		err := fmt.Errorf("NextDocument: %s", err)
		return 0, 0, err
	}

	// Drain the image
	n, err := io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()

	if err != nil && err != io.EOF {
		err := fmt.Errorf("NextDocument: %s", err)
		return 0, rsp.StatusCode, err
	}

	// Analyze HTTP status code
	if rsp.StatusCode/100 != 2 {
		err := fmt.Errorf("NextDocument: HTTP %s", rsp.Status)
		return 0, rsp.StatusCode, err
	}

	return n, rsp.StatusCode, nil
}

// DoDELETE sends eSCL DELETE request.
func DoDELETE(img *url.URL) error {
	log("DoDELETE")

	// Make HTTP request
	rq := &http.Request{
		Method: "DELETE",
		URL:    img,
		Header: make(http.Header),
	}

	rq.Header.Set("Connection", "close")
	rq = rq.WithContext(LogContext)

	// Send HTTP request and get the response
	//
	// Make sure this request always use a fresh TCP connection.
	rsp, err := HTTPClientNoKeepAlives.Do(rq)
	logHTTPExchange(rq, rsp, err)

	if err != nil {
		err := fmt.Errorf("DELETE: %s", err)
		return err
	}

	io.Copy(io.Discard, rsp.Body)
	rsp.Body.Close()

	return nil
}

// Conn wraps net.Conn and adds trace
type Conn struct {
	net.Conn
}

var (
	connNext  atomic.Int32
	connNames = make(map[string]int32)
	connLock  sync.Mutex
)

// wrapConn wraps net.Conn into the Conn structure
func wrapConn(conn net.Conn) *Conn {
	n := connNext.Add(1) + 1
	wrapped := &Conn{conn}

	connLock.Lock()
	connNames[conn.LocalAddr().String()] = n
	connLock.Unlock()

	wrapped.Log("created (%s->%s)",
		conn.LocalAddr(), conn.RemoteAddr())

	return wrapped
}

// DialContext opens a new TCP Conn
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, network, addr)
	if err == nil {
		conn = wrapConn(conn)
	}

	return conn, err
}

// DialTLSContext opens a new TLS Conn
func DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(dialer, network, addr, config)
	if err == nil {
		return wrapConn(conn), nil
	}

	return conn, err
}

// Close closes the connection
func (c *Conn) Close() error {
	c.Log("closed")

	connLock.Lock()
	delete(connNames, c.LocalAddr().String())
	connLock.Unlock()

	return c.Conn.Close()
}

// Write writes data into the connection
func (c *Conn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	if err != nil {
		c.Log("Write: %s", err)
	}
	return n, err
}

// Read reads from into the connection
func (c *Conn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if err != nil {
		c.Log("Read: %s", err)
	}
	return n, err
}

// Log writes a log message
func (c *Conn) Log(format string, args ...any) {
	connLock.Lock()
	n := connNames[c.LocalAddr().String()]
	connLock.Unlock()

	prefix := fmt.Sprintf("Connection #%d: ", n)
	log(prefix+format, args...)
}

// The main function
func main() {
	// Validate command-line arguments
	if len(os.Args) != 2 {
		usage()
	}

	// Parse and canonicalize URL
	base, err := URLParse(os.Args[1])
	if err != nil {
		die("%s", err)
	}

	// Initialize logging
	LogFile, err = os.OpenFile(LogFileName,
		os.O_WRONLY|os.O_APPEND|os.O_CREATE,
		0644)

	if err != nil {
		die("%s", err)
	}

	LogContext = httptrace.WithClientTrace(context.Background(),
		&httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				connLock.Lock()
				n := connNames[info.Conn.LocalAddr().String()]
				connLock.Unlock()

				flags := []string{}
				if info.Reused {
					flags = append(flags, "reused")
				}

				if info.WasIdle {
					flags = append(flags, "was-idle")
				}

				if !info.Reused && !info.WasIdle {
					flags = append(flags, "new")
				}

				log("Connection #%d: allocated (%s)",
					n, strings.Join(flags, " "))

			},

			PutIdleConn: func(err error) {
				if err == nil {
					err = errors.New("OK")
				}
				log("PutIdleConn: %s", err)
			},
		})

	http.DefaultClient.CheckRedirect = func(rq *http.Request, via []*http.Request) error {
		log("Redirect %s", rq.URL)
		for _, v := range via {
			log("     via %s", v.URL)
		}
		return nil
	}

	// Perform scanning
	log("================================")

	img, err := DoScanJobs(base)

	if err != nil {
		die("%s", err)
	}

	for {
		n, status, err := DoNextDocument(img)
		if status == http.StatusServiceUnavailable {
			time.Sleep(time.Second)
			log("Retryinng")
			continue
		}

		if err != nil {
			// Don't die here; we still need to cleanup
			log("%s", err)
			break
		}
		log("Image length: %d bytes", n)
	}

	DoDELETE(img)
}
