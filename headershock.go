// HeaderShock - amazing HTTP header fuzzer
// Author: Vahe Demirkhanyan

package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

type TestResult struct {
	Name       string
	StatusCode int
	Headers    http.Header
	Body       string
	Errors     []string
	Request    string
	Duration   time.Duration
}

type RequestOptions struct {
	Method      string
	URL         string
	Headers     map[string][]string
	Body        string
	Description string
	UseRaw      bool
	Timeout     time.Duration
}

type FuzzerConfig struct {
	TargetURL    string
	Delay        time.Duration
	Depth        string
	UseRawSocket bool
	Verbose      bool
	Threads      int
	Timeout      time.Duration
	UserAgent    string
	SaveResults  bool
	OutputFile   string
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func printWithColor(color, format string, args ...interface{}) {
	fmt.Printf("%s%s%s\n", color, fmt.Sprintf(format, args...), ColorReset)
}

func sendRawRequest(opts RequestOptions) TestResult {
	result := TestResult{
		Name:    opts.Description,
		Headers: make(http.Header),
		Errors:  []string{},
	}

	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse URL: %v", err))
		return result
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}

	requestLines := []string{fmt.Sprintf("%s %s HTTP/1.1", opts.Method, path)}

	hasHostHeader := false
	for key := range opts.Headers {
		if strings.ToLower(key) == "host" {
			hasHostHeader = true
			break
		}
	}
	if !hasHostHeader {
		requestLines = append(requestLines, fmt.Sprintf("Host: %s", host))
	}

	hasUserAgent := false
	hasAccept := false
	hasConnection := false
	for key := range opts.Headers {
		lkey := strings.ToLower(key)
		if lkey == "user-agent" {
			hasUserAgent = true
		} else if lkey == "accept" {
			hasAccept = true
		} else if lkey == "connection" {
			hasConnection = true
		}
	}

	if !hasUserAgent {
		requestLines = append(requestLines, "User-Agent: HeaderShock/1.0")
	}
	if !hasAccept {
		requestLines = append(requestLines, "Accept: */*")
	}
	if !hasConnection {
		requestLines = append(requestLines, "Connection: close")
	}

	for key, values := range opts.Headers {
		for _, value := range values {
			requestLines = append(requestLines, fmt.Sprintf("%s: %s", key, value))
		}
	}

	if opts.Body != "" && !strings.Contains(strings.ToLower(strings.Join(requestLines, " ")), "content-length") {
		requestLines = append(requestLines, fmt.Sprintf("Content-Length: %d", len(opts.Body)))
	}

	requestLines = append(requestLines, "")

	if opts.Body != "" {
		requestLines = append(requestLines, opts.Body)
	}

	rawRequest := strings.Join(requestLines, "\r\n")
	result.Request = rawRequest

	start := time.Now()
	var conn net.Conn
	network := "tcp"
	address := net.JoinHostPort(host, port)

	if parsedURL.Scheme == "https" {
		// TLS with more options for fuzzing
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // skip this (certs)
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			CipherSuites:       nil, // def
		}

		dialer := &net.Dialer{
			Timeout: opts.Timeout,
		}

		tlsConn, err := tls.DialWithDialer(dialer, network, address, tlsConfig)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("TLS connection error: %v", err))
			return result
		}
		conn = tlsConn
	} else {
		var err error
		conn, err = net.DialTimeout(network, address, opts.Timeout)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Connection error: %v", err))
			return result
		}
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(opts.Timeout)); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to set deadline: %v", err))
		return result
	}

	if _, err := conn.Write([]byte(rawRequest)); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to send request: %v", err))
		return result
	}

	buffer := make([]byte, 65536) // 64K buffer
	var responseData bytes.Buffer
	for {
		if err := conn.SetReadDeadline(time.Now().Add(time.Second * 5)); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to set read deadline: %v", err))
			break
		}

		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "timeout") {
				result.Errors = append(result.Errors, fmt.Sprintf("Read error: %v", err))
			}
			break
		}

		responseData.Write(buffer[:n])

		if responseData.Len() > 16384 {
			break
		}
	}

	result.Duration = time.Since(start)

	if responseData.Len() > 0 {
		parseRawResponse(responseData.Bytes(), &result)
	} else {
		result.Errors = append(result.Errors, "No response data received")
	}

	return result
}

func parseRawResponse(responseData []byte, result *TestResult) {
	response := string(responseData)

	var headerSection, body string
	if parts := strings.SplitN(response, "\r\n\r\n", 2); len(parts) > 1 {
		headerSection, body = parts[0], parts[1]
	} else if parts := strings.SplitN(response, "\n\n", 2); len(parts) > 1 {
		headerSection, body = parts[0], parts[1]
	} else {
		headerSection = response
	}

	headerLines := strings.Split(headerSection, "\r\n")
	if len(headerLines) <= 1 {
		headerLines = strings.Split(headerSection, "\n")
	}

	if len(headerLines) > 0 {
		statusLine := headerLines[0]
		if strings.HasPrefix(statusLine, "HTTP/") {
			parts := strings.SplitN(statusLine, " ", 3)
			if len(parts) >= 2 {
				if code, err := fmt.Sscanf(parts[1], "%d", &result.StatusCode); err != nil || code != 1 {
					result.StatusCode = 0
					result.Errors = append(result.Errors, "Failed to parse status code")
				}
			}
		}
	}

	for _, line := range headerLines[1:] {
		if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			result.Headers.Add(key, value)
		}
	}

	if len(body) > 1000 {
		result.Body = body[:1000]
	} else {
		result.Body = body
	}
}

func sendStandardRequest(opts RequestOptions) TestResult {
	result := TestResult{
		Name:    opts.Description,
		Headers: make(http.Header),
		Errors:  []string{},
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableCompression: false,
		DialContext: (&net.Dialer{
			Timeout:   opts.Timeout,
			KeepAlive: 0, 
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// dn't follow redirects - we want to see the actual redirect
			return http.ErrUseLastResponse
		},
	}

	//prepare the request
	var bodyReader io.Reader
	if opts.Body != "" {
		bodyReader = strings.NewReader(opts.Body)
	}

	req, err := http.NewRequest(opts.Method, opts.URL, bodyReader)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to create request: %v", err))
		return result
	}

	for key, values := range opts.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	var reqDump strings.Builder
	reqDump.WriteString(fmt.Sprintf("%s %s\n", req.Method, req.URL.String()))
	for k, v := range req.Header {
		reqDump.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	result.Request = reqDump.String()

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Request failed: %v", err))
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Headers = resp.Header

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read response body: %v", err))
	} else {
		if len(bodyBytes) > 1000 {
			result.Body = string(bodyBytes[:1000])
		} else {
			result.Body = string(bodyBytes)
		}
	}

	result.Duration = time.Since(start)
	return result
}

func sendRequest(opts RequestOptions) TestResult {
	if opts.UseRaw {
		return sendRawRequest(opts)
	}

	if containsDuplicateHeaders(opts.Headers) {
		newOpts := opts
		newOpts.UseRaw = true
		return sendRawRequest(newOpts)
	}

	return sendStandardRequest(opts)
}

func containsDuplicateHeaders(headers map[string][]string) bool {
	headerCounts := make(map[string]int)
	for header := range headers {
		headerCounts[strings.ToLower(header)]++
	}

	for _, count := range headerCounts {
		if count > 1 {
			return true
		}
	}
	return false
}

func printResult(result TestResult, baselineResult *TestResult, verbose bool) {
	printWithColor(ColorYellow, "Test: %s", result.Name)

	if len(result.Errors) > 0 {
		printWithColor(ColorRed, "Errors: %s", strings.Join(result.Errors, ", "))
		return
	}

	statusColor := ColorGreen
	if result.StatusCode >= 400 {
		statusColor = ColorRed
	} else if result.StatusCode >= 300 {
		statusColor = ColorYellow
	}
	printWithColor(statusColor, "Status: %d", result.StatusCode)
	printWithColor(ColorCyan, "Response time: %v", result.Duration)

	if verbose {
		printWithColor(ColorCyan, "Headers:")
		for key, values := range result.Headers {
			fmt.Printf("  %s: %s\n", key, strings.Join(values, ", "))
		}
	} else {
		headerCount := len(result.Headers)
		printWithColor(ColorCyan, "Headers: %d headers received", headerCount)
	}

	if verbose {
		if len(result.Body) > 0 {
			printWithColor(ColorWhite, "Body Snippet: %s", truncateString(result.Body, 200))
		} else {
			printWithColor(ColorWhite, "Body: Empty")
		}
	}

	if baselineResult != nil {
		differences := compareResponses(*baselineResult, result)
		if len(differences) > 0 {
			printWithColor(ColorPurple, "Differences from baseline:")
			for _, diff := range differences {
				fmt.Printf("  - %s\n", diff)
			}
		}

		newHeaders := findNewHeaders(baselineResult.Headers, result.Headers)
		if len(newHeaders) > 0 {
			printWithColor(ColorRed, "New headers appeared: %s", strings.Join(newHeaders, ", "))
		}
	}

	infoLeaks := checkBodyForInfo(result.Body)
	if len(infoLeaks) > 0 {
		printWithColor(ColorRed, "Potential info leaks in body:")
		for _, leak := range infoLeaks {
			fmt.Printf("  - %s\n", leak)
		}
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func compareResponses(baseline, test TestResult) []string {
	var differences []string

	if baseline.StatusCode != test.StatusCode {
		differences = append(differences, fmt.Sprintf("Status code: %d -> %d", baseline.StatusCode, test.StatusCode))
	}

	for header, baseValue := range baseline.Headers {
		testValue, exists := test.Headers[header]
		if !exists {
			differences = append(differences, fmt.Sprintf("Header %s: '%s' -> Not present", header, strings.Join(baseValue, ", ")))
		} else if !headerValuesEqual(baseValue, testValue) {
			differences = append(differences, fmt.Sprintf("Header %s: '%s' -> '%s'", header, strings.Join(baseValue, ", "), strings.Join(testValue, ", ")))
		}
	}

	if baseline.Body != test.Body {
		differences = append(differences, "Body content differs")
	}

	return differences
}

func headerValuesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func findNewHeaders(baseline, test http.Header) []string {
	var newHeaders []string
	
	for header := range test {
		if _, exists := baseline[header]; !exists {
			newHeaders = append(newHeaders, header)
		}
	}
	
	return newHeaders
}

func checkBodyForInfo(body string) []string {
	patterns := []struct {
		regex string
		desc  string
	}{
		{`stack trace|stacktrace`, "Stack trace"},
		{`exception|Exception|Error:|error:|RuntimeError|Runtime Error`, "Exception/Error messages"},
		{`version\s+\d+\.\d+(\.\d+)?`, "Version information"},
		{`server:\s*[\w\-\.\/]+`, "Server software details"},
		{`at\s+[a-zA-Z0-9_.]+\([^)]*:[0-9]+\)`, "Code location in error"},
		{`debug|DEBUG`, "Debug information"},
		{`traceback|Traceback`, "Traceback information"},
		{`undefined\s+variable|undefined\s+method|undefined\s+property`, "Undefined variable/method"},
		{`syntax\s+error`, "Syntax error"},
		{`runtime\s+error`, "Runtime error"},
		{`database\s+error|DB Error|SQL syntax|ORA-\d+`, "Database error"},
		{`([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})`, "Email address"},
		{`(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`, "IP address"},
		{`([A-Za-z]:)?[\\/](?:[^\\/]+[\\/])*[^\\/]+\.[a-zA-Z0-9]{2,4}`, "File path"},
		{`([a-zA-Z0-9_-]+):([^\s]+)`, "Possible credentials"},
		{`confidential|internal|private`, "Confidential information markers"},
	}

	var findings []string
	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern.regex)
		matches := re.FindAllString(body, -1)
		if len(matches) > 0 {
			uniqueMatches := make(map[string]bool)
			for _, match := range matches {
				uniqueMatches[match] = true
			}
			
			keys := make([]string, 0, len(uniqueMatches))
			for k := range uniqueMatches {
				keys = append(keys, k)
			}
			
			matchText := ""
			if len(keys) > 3 {
				matchText = fmt.Sprintf("%s (and %d more)", strings.Join(keys[:3], ", "), len(keys)-3)
			} else {
				matchText = strings.Join(keys, ", ")
			}
			
			findings = append(findings, fmt.Sprintf("%s found: %s", pattern.desc, matchText))
		}
	}
	return findings
}

func generateTestCases(targetURL string, depth string, useRawSocket bool) []RequestOptions {
	var tests []RequestOptions

	tests = append(tests, []RequestOptions{
		{
			Method:      "GET",
			URL:         targetURL + "/nonexistent",
			Description: "GET nonexistent path",
			UseRaw:      useRawSocket,
		},
		{
			Method:      "POST",
			URL:         targetURL,
			Description: "POST with no body",
			UseRaw:      useRawSocket,
		},
		{
			Method:      "POST",
			URL:         targetURL,
			Body:        "{invalid: json",
			Description: "POST with malformed JSON",
			UseRaw:      useRawSocket,
		},
		{
			Method:      "PUT",
			URL:         targetURL,
			Body:        "test",
			Description: "PUT with body",
			UseRaw:      useRawSocket,
		},
		{
			Method:      "DELETE",
			URL:         targetURL,
			Description: "DELETE request",
			UseRaw:      useRawSocket,
		},
		{
			Method:      "TRACE",
			URL:         targetURL,
			Description: "TRACE request",
			UseRaw:      useRawSocket,
		},
		{
			Method:      "TEST",
			URL:         targetURL,
			Description: "Non-standard method",
			UseRaw:      useRawSocket,
		},
		{
			Method:      "GEt",
			URL:         targetURL,
			Description: "Misspelled method",
			UseRaw:      useRawSocket,
		},
		{
			Method:      generateRandomString(8),
			URL:         targetURL,
			Description: "Random method",
			UseRaw:      useRawSocket,
		},
		{
			Method:      "GET",
			URL:         targetURL,
			Headers:     map[string][]string{"Host": {"localhost", "example.com"}},
			Description: "Multiple Host headers",
			UseRaw:      true, // Always use raw for multiple headers
		},
		{
			Method:      "GET",
			URL:         targetURL,
			Headers:     map[string][]string{"User-Agent": {strings.Repeat("A", 1000)}},
			Description: "Excessively long User-Agent",
			UseRaw:      useRawSocket,
		},
		{
			Method:      "GET",
			URL:         targetURL,
			Headers:     map[string][]string{"X-Custom": {"\x00\x01invalid"}},
			Description: "Header with null bytes",
			UseRaw:      useRawSocket,
		},
	}...)

	if depth == "medium" || depth == "deep" {
		tests = append(tests, []RequestOptions{
			{
				Method:      "GET",
				URL:         targetURL + "?param=" + generateRandomString(10),
				Description: "GET with random query param",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "POST",
				URL:         targetURL,
				Headers:     map[string][]string{"Content-Length": {"5", "10"}},
				Body:        "test",
				Description: "Duplicate Content-Length",
				UseRaw:      true, // Always use raw
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"Upgrade": {"websocket"}},
				Description: "WebSocket upgrade attempt",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{
					"Transfer-Encoding": {"chunked"},
					"Content-Length":    {"5"},
				},
				Body:        "0\r\n\r\n",
				Description: "Mixed Transfer-Encoding and Content-Length",
				UseRaw:      true, // Always use raw
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"Cookie": {"session="+generateRandomString(32)}},
				Description: "Random session cookie",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"X-Forwarded-For": {"127.0.0.1"}},
				Description: "X-Forwarded-For: localhost",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"X-Forwarded-Host": {"localhost"}},
				Description: "X-Forwarded-Host: localhost",
				UseRaw:      useRawSocket,
			},
		}...)
	}

	// Deep depth tests
	if depth == "deep" {
		tests = append(tests, []RequestOptions{
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"Transfer-Encoding": {"chunked"}},
				Body:        "5\r\ntest\r\n0\r\n\r\ninvalid",
				Description: "Malformed chunked encoding",
				UseRaw:      true, // Always use raw
			},
			{
				Method:      "PRI",
				URL:         targetURL,
				Description: "HTTP/2 PRI method",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"Accept": {strings.Repeat("A", 5000)}},
				Description: "Massive Accept header",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL + "/../secret",
				Description: "Path traversal attempt",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"Content-Length": {"-1"}},
				Description: "Negative Content-Length",
				UseRaw:      true, // Always use raw
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"Range": {"bytes=0-,-1"}},
				Description: "Multiple byte ranges",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "POST",
				URL:         targetURL,
				Headers:     map[string][]string{"Expect": {"100-continue"}},
				Body:        "test",
				Description: "Expect: 100-continue header",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"If-None-Match": {"*"}},
				Description: "If-None-Match: *",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"Connection": {"keep-alive, Transfer-Encoding"}},
				Description: "Connection: smuggling attempt",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "POST",
				URL:         targetURL,
				Headers:     map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
				Body:        "a=1&a=2&a[]=3",
				Description: "Duplicate and array parameters",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"Authorization": {"Basic " + generateRandomString(20)}},
				Description: "Invalid Basic auth",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "POST",
				URL:         targetURL,
				Headers:     map[string][]string{"Content-Type": {"multipart/form-data; boundary=boundary"}},
				Body:        "--boundary\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\nvalue\r\n--boundary--\r\n",
				Description: "Simple multipart form data",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL + "/." + generateRandomString(5),
				Description: "Hidden file path",
				UseRaw:      useRawSocket,
			},
			{
Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"Cache-Control": {"no-cache, max-age=0, must-revalidate"}},
				Description: "Multiple cache control directives",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "PATCH",
				URL:         targetURL,
				Body:        "[{\"op\": \"replace\", \"path\": \"/test\", \"value\": \"test\"}]",
				Description: "PATCH with JSON Patch format",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "POST",
				URL:         targetURL,
				Headers:     map[string][]string{"Content-Type": {"application/xml"}},
				Body:        "<?xml version=\"1.0\"?><test>value</test>",
				Description: "POST with XML body",
				UseRaw:      useRawSocket,
			},
			{
				Method:      "GET",
				URL:         targetURL,
				Headers:     map[string][]string{"Accept-Encoding": {"gzip, deflate, br, compress, identity, *"}},
				Description: "Multiple Accept-Encoding values",
				UseRaw:      useRawSocket,
			},
		}...)
	}

	return tests
}

// Saving to file
func saveResultsToFile(results []TestResult, baselineResult *TestResult, outputFile string) error {
	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	f.WriteString("# HTTP Fuzzer Results\n")
	f.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	if baselineResult != nil {
		f.WriteString("## Baseline Request\n")
		f.WriteString(fmt.Sprintf("- Status: %d\n", baselineResult.StatusCode))
		f.WriteString("- Headers:\n")
		for key, values := range baselineResult.Headers {
			f.WriteString(fmt.Sprintf("  - %s: %s\n", key, strings.Join(values, ", ")))
		}
		f.WriteString("\n")
	}

	f.WriteString("## Test Results\n\n")
	for _, result := range results {
		f.WriteString(fmt.Sprintf("### %s\n", result.Name))
		
		if len(result.Errors) > 0 {
			f.WriteString(fmt.Sprintf("- Errors: %s\n", strings.Join(result.Errors, ", ")))
			f.WriteString("\n")
			continue
		}
		
		f.WriteString(fmt.Sprintf("- Status: %d\n", result.StatusCode))
		f.WriteString(fmt.Sprintf("- Response Time: %v\n", result.Duration))
		
		// Headers
		f.WriteString("- Headers:\n")
		for key, values := range result.Headers {
			f.WriteString(fmt.Sprintf("  - %s: %s\n", key, strings.Join(values, ", ")))
		}
		
		// Differences from baseline
		if baselineResult != nil {
			differences := compareResponses(*baselineResult, result)
			if len(differences) > 0 {
				f.WriteString("- Differences from baseline:\n")
				for _, diff := range differences {
					f.WriteString(fmt.Sprintf("  - %s\n", diff))
				}
			}
		}
		
		// Information leaks
		infoLeaks := checkBodyForInfo(result.Body)
		if len(infoLeaks) > 0 {
			f.WriteString("- Potential information leaks:\n")
			for _, leak := range infoLeaks {
				f.WriteString(fmt.Sprintf("  - %s\n", leak))
			}
		}
		
		f.WriteString("\n")
	}

	return nil
}

func main() {
	targetURL := flag.String("url", "", "Target URL (e.g., http://example.com)")
	delay := flag.Float64("delay", 0.5, "Base delay between requests in seconds")
	depth := flag.String("depth", "medium", "Testing depth: light, medium, or deep")
	useRaw := flag.Bool("raw", false, "Force use of raw sockets for all requests")
	verbose := flag.Bool("verbose", false, "Show more detailed output")
	threads := flag.Int("threads", 1, "Number of concurrent threads")
	timeout := flag.Float64("timeout", 10.0, "Timeout for requests in seconds")
	saveResults := flag.Bool("save", false, "Save results to file")
	outputFile := flag.String("output", "fuzzer-results.md", "Output file for results")
	userAgent := flag.String("user-agent", "HeaderShock/1.0", "User-Agent string to use")
	flag.Parse()

	if *targetURL == "" {
		if flag.NArg() > 0 {
			*targetURL = flag.Arg(0)
		} else {
			printWithColor(ColorRed, "Error: Target URL is required")
			flag.Usage()
			os.Exit(1)
		}
	}

	if *depth != "light" && *depth != "medium" && *depth != "deep" {
		printWithColor(ColorRed, "Error: Depth must be one of: light, medium, deep")
		flag.Usage()
		os.Exit(1)
	}

	config := FuzzerConfig{
		TargetURL:    *targetURL,
		Delay:        time.Duration(float64(time.Second) * *delay),
		Depth:        *depth,
		UseRawSocket: *useRaw,
		Verbose:      *verbose,
		Threads:      *threads,
		Timeout:      time.Duration(float64(time.Second) * *timeout),
		UserAgent:    *userAgent,
		SaveResults:  *saveResults,
		OutputFile:   *outputFile,
	}

	rand.Seed(time.Now().UnixNano())

	fmt.Printf(`
%s===========================================
    HeaderShock - Advanced HTTP Fuzzer
===========================================
%s`, ColorBlue, ColorReset)

	printWithColor(ColorBlue, "Target: %s", config.TargetURL)
	printWithColor(ColorBlue, "Depth: %s", config.Depth)
	printWithColor(ColorBlue, "Threads: %d", config.Threads)
	printWithColor(ColorBlue, "Raw socket mode: %v", config.UseRawSocket)
	fmt.Println()

	// the baseline
	printWithColor(ColorBlue, "Sending baseline request...")
	baselineOpts := RequestOptions{
		Method:      "GET",
		URL:         config.TargetURL,
		Description: "Baseline GET",
		UseRaw:      config.UseRawSocket,
		Timeout:     config.Timeout,
	}
	baselineResult := sendRequest(baselineOpts)
	printResult(baselineResult, nil, config.Verbose)

	if len(baselineResult.Errors) > 0 {
		printWithColor(ColorRed, "Baseline request failed. Continuing anyway, but comparison will be limited.")
	}

	// test cases
	tests := generateTestCases(config.TargetURL, config.Depth, config.UseRawSocket)
	printWithColor(ColorBlue, "Generated %d test cases", len(tests))

	printWithColor(ColorBlue, "Starting tests with %d threads...", config.Threads)
	var wg sync.WaitGroup
	resultsChan := make(chan TestResult, len(tests))
	semaphore := make(chan struct{}, config.Threads)

	for _, test := range tests {
		wg.Add(1)
		go func(opts RequestOptions) {
			defer wg.Done()
			semaphore <- struct{}{}        
			defer func() { <-semaphore }() 

			jitter := time.Duration(rand.Float64() * float64(config.Delay))
			time.Sleep(config.Delay + jitter)

			opts.Timeout = config.Timeout
			result := sendRequest(opts)
			resultsChan <- result
			printResult(result, &baselineResult, config.Verbose)
		}(test)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []TestResult
	for result := range resultsChan {
		results = append(results, result)
	}

	printWithColor(ColorBlue, "\nSummary of Key Findings:")
	interestingFindings := 0
	for _, result := range results {
		if len(result.Errors) > 0 {
			continue
		}

		var findings []string
		if result.StatusCode >= 500 || (result.StatusCode >= 400 && result.StatusCode != 404) || result.StatusCode == 405 {
			findings = append(findings, fmt.Sprintf("Interesting status code: %d", result.StatusCode))
		}

		if baselineResult.Headers.Get("Server") != result.Headers.Get("Server") &&
			result.Headers.Get("Server") != "" {
			findings = append(findings, fmt.Sprintf("Server header changed to '%s'", result.Headers.Get("Server")))
		}

		newHeaders := findNewHeaders(baselineResult.Headers, result.Headers)
		if len(newHeaders) > 0 {
			findings = append(findings, fmt.Sprintf("Introduced new headers: %s", strings.Join(newHeaders, ", ")))
		}

		infoLeaks := checkBodyForInfo(result.Body)
		if len(infoLeaks) > 0 {
			findings = append(findings, fmt.Sprintf("Found %d potential info leaks", len(infoLeaks)))
		}

		if len(findings) > 0 {
			interestingFindings++
			printWithColor(ColorYellow, "%s:", result.Name)
			for _, finding := range findings {
				fmt.Printf("  - %s\n", finding)
			}
		}
	}

	if interestingFindings == 0 {
		printWithColor(ColorGreen, "No major anomalies detected in responses.")
	} else {
		printWithColor(ColorYellow, "Found %d interesting responses out of %d tests.", interestingFindings, len(tests))
	}

	if config.SaveResults {
		printWithColor(ColorBlue, "Saving results to %s...", config.OutputFile)
		if err := saveResultsToFile(results, &baselineResult, config.OutputFile); err != nil {
			printWithColor(ColorRed, "Error saving results: %v", err)
		} else {
			printWithColor(ColorGreen, "Results saved successfully.")
		}
	}
}