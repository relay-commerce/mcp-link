package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"encoding/base64"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// sseSession represents an active SSE connection.
type sseSession struct {
	writer              http.ResponseWriter
	flusher             http.Flusher
	done                chan struct{}
	eventQueue          chan string // Channel for queuing events
	sessionID           string
	notificationChannel chan mcp.JSONRPCNotification
	initialized         atomic.Bool
}

// SSEContextFunc is a function that takes an existing context and the current
// request and returns a potentially modified context based on the request
// content. This can be used to inject context values from headers, for example.
type SSEContextFunc func(ctx context.Context, r *http.Request) context.Context

func (s *sseSession) SessionID() string {
	return s.sessionID
}

func (s *sseSession) NotificationChannel() chan<- mcp.JSONRPCNotification {
	return s.notificationChannel
}

func (s *sseSession) Initialize() {
	s.initialized.Store(true)
}

func (s *sseSession) Initialized() bool {
	return s.initialized.Load()
}

var _ server.ClientSession = (*sseSession)(nil)

// SSEServer implements a Server-Sent Events (SSE) based MCP server.
// It provides real-time communication capabilities over HTTP using the SSE protocol.
type SSEServer struct {
	// server          *server.MCPServer
	servers         map[string]*server.MCPServer
	serversMutex    sync.RWMutex
	baseURL         string
	basePath        string
	messageEndpoint string
	sseEndpoint     string
	sessions        sync.Map
	srv             *http.Server
	contextFunc     SSEContextFunc
}

// SSEOption defines a function type for configuring SSEServer
type SSEOption func(*SSEServer)

// WithBaseURL sets the base URL for the SSE server
func WithBaseURL(baseURL string) SSEOption {
	return func(s *SSEServer) {
		if baseURL != "" {
			u, err := url.Parse(baseURL)
			if err != nil {
				return
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return
			}
			// Check if the host is empty or only contains a port
			if u.Host == "" || strings.HasPrefix(u.Host, ":") {
				return
			}
			if len(u.Query()) > 0 {
				return
			}
		}
		s.baseURL = strings.TrimSuffix(baseURL, "/")
	}
}

// Add a new option for setting base path
func WithBasePath(basePath string) SSEOption {
	return func(s *SSEServer) {
		// Ensure the path starts with / and doesn't end with /
		if !strings.HasPrefix(basePath, "/") {
			basePath = "/" + basePath
		}
		s.basePath = strings.TrimSuffix(basePath, "/")
	}
}

// WithMessageEndpoint sets the message endpoint path
func WithMessageEndpoint(endpoint string) SSEOption {
	return func(s *SSEServer) {
		s.messageEndpoint = endpoint
	}
}

// WithSSEEndpoint sets the SSE endpoint path
func WithSSEEndpoint(endpoint string) SSEOption {
	return func(s *SSEServer) {
		s.sseEndpoint = endpoint
	}
}

// WithHTTPServer sets the HTTP server instance
func WithHTTPServer(srv *http.Server) SSEOption {
	return func(s *SSEServer) {
		s.srv = srv
	}
}

// WithContextFunc sets a function that will be called to customise the context
// to the server using the incoming request.
func WithSSEContextFunc(fn SSEContextFunc) SSEOption {
	return func(s *SSEServer) {
		s.contextFunc = fn
	}
}

// NewSSEServer creates a new SSE server instance with the given MCP server and options.
func NewSSEServer(opts ...SSEOption) *SSEServer {
	s := &SSEServer{
		servers:         map[string]*server.MCPServer{},
		sseEndpoint:     "/sse",
		messageEndpoint: "/message",
	}

	// Apply all options
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Start begins serving SSE connections on the specified address.
// It sets up HTTP handlers for SSE and message endpoints.
func (s *SSEServer) Start(addr string) error {
	s.srv = &http.Server{
		Addr:    addr,
		Handler: s,
	}

	return s.srv.ListenAndServe()
}

// Shutdown gracefully stops the SSE server, closing all active sessions
// and shutting down the HTTP server.
func (s *SSEServer) Shutdown(ctx context.Context) error {
	if s.srv != nil {
		s.sessions.Range(func(key, value interface{}) bool {
			if session, ok := value.(*sseSession); ok {
				close(session.done)
			}
			s.sessions.Delete(key)
			return true
		})

		return s.srv.Shutdown(ctx)
	}
	return nil
}

// handleSSE handles incoming SSE connection requests.
// It sets up appropriate headers and creates a new session for the client.
func (s *SSEServer) handleSSE(mcpServer *server.MCPServer, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	sessionID := uuid.New().String()
	session := &sseSession{
		writer:              w,
		flusher:             flusher,
		done:                make(chan struct{}),
		eventQueue:          make(chan string, 100), // Buffer for events
		sessionID:           sessionID,
		notificationChannel: make(chan mcp.JSONRPCNotification, 100),
	}

	// Protect map write with mutex
	s.serversMutex.Lock()
	s.servers[sessionID] = mcpServer
	s.serversMutex.Unlock()

	s.sessions.Store(sessionID, session)
	defer s.sessions.Delete(sessionID)

	// Use read lock when accessing the map for reading
	s.serversMutex.RLock()
	mcpServer = s.servers[sessionID]
	s.serversMutex.RUnlock()

	if err := mcpServer.RegisterSession(session); err != nil {
		http.Error(w, fmt.Sprintf("Session registration failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer func() {
		s.serversMutex.Lock()
		defer s.serversMutex.Unlock()
		mcpServer.UnregisterSession(sessionID)
		s.sessions.Delete(sessionID)
	}()

	// Start notification handler for this session
	go func() {
		for {
			select {
			case notification := <-session.notificationChannel:
				eventData, err := json.Marshal(notification)
				if err == nil {
					select {
					case session.eventQueue <- fmt.Sprintf("event: message\ndata: %s\n\n", eventData):
						// Event queued successfully
					case <-session.done:
						return
					}
				}
			case <-session.done:
				return
			case <-r.Context().Done():
				return
			}
		}
	}()

	messageEndpoint := fmt.Sprintf("%s?sessionId=%s", s.CompleteMessageEndpoint(), sessionID)

	// Send the initial endpoint event
	fmt.Fprintf(w, "event: endpoint\ndata: %s\r\n\r\n", messageEndpoint)
	flusher.Flush()

	// Main event loop - this runs in the HTTP handler goroutine
	for {
		select {
		case event := <-session.eventQueue:
			// Write the event to the response
			fmt.Fprint(w, event)
			flusher.Flush()
		case <-r.Context().Done():
			close(session.done)
			return
		}
	}
}

// handleMessage processes incoming JSON-RPC messages from clients and sends responses
// back through both the SSE connection and HTTP response.
func (s *SSEServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSONRPCError(w, nil, mcp.INVALID_REQUEST, "Method not allowed")
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		s.writeJSONRPCError(w, nil, mcp.INVALID_PARAMS, "Missing sessionId")
		return
	}

	sessionI, ok := s.sessions.Load(sessionID)
	if !ok {
		s.writeJSONRPCError(w, nil, mcp.INVALID_PARAMS, "Invalid session ID")
		return
	}
	session := sessionI.(*sseSession)

	// Use read lock when accessing the map for reading
	s.serversMutex.RLock()
	server := s.servers[sessionID]
	s.serversMutex.RUnlock()

	// Use the retrieved server
	ctx := server.WithContext(r.Context(), session)
	if s.contextFunc != nil {
		ctx = s.contextFunc(ctx, r)
	}

	// Parse message as raw JSON
	var rawMessage json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&rawMessage); err != nil {
		s.writeJSONRPCError(w, nil, mcp.PARSE_ERROR, "Parse error")
		return
	}

	// Process message through MCPServer
	response := server.HandleMessage(ctx, rawMessage)

	// Only send response if there is one (not for notifications)
	if response != nil {
		eventData, _ := json.Marshal(response)

		// Queue the event for sending via SSE
		select {
		case session.eventQueue <- fmt.Sprintf("event: message\ndata: %s\n\n", eventData):
			// Event queued successfully
		case <-session.done:
			// Session is closed, don't try to queue
		default:
			// Queue is full, could log this
		}

		// Send HTTP response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(response)
	} else {
		// For notifications, just send 202 Accepted with no body
		w.WriteHeader(http.StatusAccepted)
	}
}

// writeJSONRPCError writes a JSON-RPC error response with the given error details.
func (s *SSEServer) writeJSONRPCError(
	w http.ResponseWriter,
	id interface{},
	code int,
	message string,
) {
	response := createErrorResponse(id, code, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(response)
}

// SendEventToSession sends an event to a specific SSE session identified by sessionID.
// Returns an error if the session is not found or closed.
func (s *SSEServer) SendEventToSession(
	sessionID string,
	event interface{},
) error {
	sessionI, ok := s.sessions.Load(sessionID)
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	session := sessionI.(*sseSession)

	eventData, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Queue the event for sending via SSE
	select {
	case session.eventQueue <- fmt.Sprintf("event: message\ndata: %s\n\n", eventData):
		return nil
	case <-session.done:
		return fmt.Errorf("session closed")
	default:
		return fmt.Errorf("event queue full")
	}
}
func (s *SSEServer) GetUrlPath(input string) (string, error) {
	parse, err := url.Parse(input)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL %s: %w", input, err)
	}
	return parse.Path, nil
}

func (s *SSEServer) CompleteSseEndpoint() string {
	return s.baseURL + s.basePath + s.sseEndpoint
}
func (s *SSEServer) CompleteSsePath() string {
	path, err := s.GetUrlPath(s.CompleteSseEndpoint())
	if err != nil {
		return s.basePath + s.sseEndpoint
	}
	return path
}

func (s *SSEServer) CompleteMessageEndpoint() string {
	return s.baseURL + s.basePath + s.messageEndpoint
}
func (s *SSEServer) CompleteMessagePath() string {
	path, err := s.GetUrlPath(s.CompleteMessageEndpoint())
	if err != nil {
		return s.basePath + s.messageEndpoint
	}
	return path
}

// RequestParams holds the parameters extracted from the request URL
type RequestParams struct {
	SchemaURL string            `json:"s"`
	BaseURL   string            `json:"u"`
	Headers   map[string]string `json:"h"`
	RawBytes  []byte            `json:"b"`
	Filters   []PathFilter      `json:"f"`
	Error     error
}

// PathFilter defines a filter to include or exclude API paths
type PathFilter struct {
	Pattern string   `json:"pattern"` // Path pattern (supports glob: * for segment, ** for multiple segments)
	Methods []string `json:"methods"` // HTTP methods to filter (GET, POST, etc.); empty means all methods
	Exclude bool     `json:"exclude"` // If true, this is an exclusion filter
}

// MatchesPath checks if a path matches this filter
func (f PathFilter) MatchesPath(path string) bool {
	return matchGlob(f.Pattern, path)
}

// MatchesMethod checks if a method matches this filter
func (f PathFilter) MatchesMethod(method string) bool {
	if len(f.Methods) == 0 {
		return true // No methods specified means match all methods
	}

	for _, m := range f.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// matchGlob implements a simple glob pattern matching
// * matches any single path segment
// ** matches zero or more path segments
func matchGlob(pattern, path string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}

	// Split pattern and path into segments
	patternSegs := strings.Split(strings.Trim(pattern, "/"), "/")
	pathSegs := strings.Split(strings.Trim(path, "/"), "/")

	return matchGlobSegments(patternSegs, pathSegs)
}

// matchGlobSegments is a recursive helper for matchGlob
func matchGlobSegments(pattern, path []string) bool {
	// Base cases
	if len(pattern) == 0 {
		return len(path) == 0
	}

	// Handle ** (matches zero or more segments)
	if pattern[0] == "**" {
		// Try to match at current position
		if matchGlobSegments(pattern[1:], path) {
			return true
		}
		// Try to consume one segment of path and match again
		if len(path) > 0 {
			return matchGlobSegments(pattern, path[1:])
		}
		return false
	}

	// For normal segments or * wildcard
	if len(path) == 0 {
		return false
	}

	// * matches any segment
	if pattern[0] == "*" || pattern[0] == path[0] {
		return matchGlobSegments(pattern[1:], path[1:])
	}

	return false
}

// FilterExpression represents a single filter expression in the DSL
type FilterExpression struct {
	Include bool
	Pattern string
	Methods []string
}

// ParseFilterDSL parses a filter DSL string into a FilterDSL object
//
// The DSL syntax is as follows:
// - "+" at start means include (default), "-" means exclude
// - Path pattern follows (supports glob: * for segment, ** for multiple segments)
// - Optional ":METHOD1 METHOD2" suffix to specify HTTP methods (space-separated)
// - Multiple expressions separated by semicolons
//
// Examples:
// - "+/api/**" - Include all endpoints under /api/
// - "-/api/admin/**" - Exclude all endpoints under /api/admin/
// - "+/users/*:GET" - Include GET endpoints for /users/{id}
// - "+/**:GET;-/internal/**" - Include all GET endpoints except those under /internal/
func ParseFilterDSL(dsl string) FilterDSL {
	result := FilterDSL{}
	expressions := strings.Split(dsl, ";")

	for _, expr := range expressions {
		expr = strings.TrimSpace(expr)
		if expr == "" {
			continue
		}

		expression := FilterExpression{
			Include: true,
		}

		// Check for include/exclude prefix
		if strings.HasPrefix(expr, "+") {
			expression.Include = true
			expr = expr[1:]
		} else if strings.HasPrefix(expr, "-") {
			expression.Include = false
			expr = expr[1:]
		}

		// Check for method suffix
		parts := strings.Split(expr, ":")
		expression.Pattern = parts[0]

		if len(parts) > 1 && parts[1] != "" {
			// Methods are space-separated
			methods := strings.Fields(parts[1])
			for _, method := range methods {
				method = strings.TrimSpace(method)
				if method != "" {
					expression.Methods = append(expression.Methods, strings.ToUpper(method))
				}
			}
		}

		result.Expressions = append(result.Expressions, expression)
	}

	return result
}

// FilterDSL provides a domain-specific language for filtering API paths
type FilterDSL struct {
	Expressions []FilterExpression
}

// ToPathFilters converts the FilterDSL to a slice of PathFilter objects
func (dsl FilterDSL) ToPathFilters() []PathFilter {
	result := make([]PathFilter, 0, len(dsl.Expressions))

	for _, expr := range dsl.Expressions {
		filter := PathFilter{
			Pattern: expr.Pattern,
			Methods: expr.Methods,
			Exclude: !expr.Include,
		}
		result = append(result, filter)
	}

	return result
}

// ApplyFilters applies the specified filters to the OpenAPI paths and methods
func ApplyFilters(apis []APIEndpoint, filters []PathFilter) []APIEndpoint {
	if len(filters) == 0 {
		return apis // No filtering needed
	}

	var filteredAPIs []APIEndpoint
	for _, api := range apis {
		if ShouldIncludePath(api.Path, api.Method, filters) {
			filteredAPIs = append(filteredAPIs, api)
		}
	}

	return filteredAPIs
}

// parseRequestParams extracts parameters from the request URL query.
// If a 'code' parameter is present, it attempts to base64 decode it to get parameters.
// Otherwise, it parses individual query parameters.
func (s *SSEServer) parseRequestParams(r *http.Request) RequestParams {
	query := r.URL.Query()
	params := RequestParams{
		Headers: make(map[string]string),
	}

	// Check if we have a base64 encoded 'code' parameter
	if encodedParams := query.Get("code"); encodedParams != "" {
		// Decode base64 string
		decodedBytes, err := Base64Decode(encodedParams)
		if err != nil {
			params.Error = fmt.Errorf("failed to decode parameters: %w", err)
			return params
		}

		// Parse decoded JSON into params
		var decodedParams map[string]interface{}
		if err := json.Unmarshal(decodedBytes, &decodedParams); err != nil {
			params.Error = fmt.Errorf("failed to parse decoded parameters: %w", err)
			return params
		}

		// Extract parameters from decoded JSON
		if schema, ok := decodedParams["s"].(string); ok {
			params.SchemaURL = schema
		}
		if baseURL, ok := decodedParams["u"].(string); ok {
			params.BaseURL = baseURL
		}

		if headers, ok := decodedParams["h"].(map[string]interface{}); ok {
			for key, value := range headers {
				if strValue, ok := value.(string); ok {
					params.Headers[key] = strValue
				}
			}
		}

		// Parse filter DSL string from f parameter
		if filterDSL, ok := decodedParams["f"].(string); ok {
			dsl := ParseFilterDSL(filterDSL)
			params.Filters = append(params.Filters, dsl.ToPathFilters()...)
		}
	} else {
		// Traditional parameter parsing
		params.SchemaURL = query.Get("s")
		params.BaseURL = query.Get("u")

		h := query.Get("h")
		if h != "" {
			if err := json.Unmarshal([]byte(h), &params.Headers); err != nil {
				params.Error = fmt.Errorf("failed to parse headers: %w", err)
				return params
			}
		}

		// Parse DSL filters from f parameter (can be multiple)
		filterValues := query["f"]
		for _, filterDSL := range filterValues {
			if filterDSL != "" {
				dsl := ParseFilterDSL(filterDSL)
				params.Filters = append(params.Filters, dsl.ToPathFilters()...)
			}
		}
	}

	// Load schema content if provided
	if params.SchemaURL != "" {
		var err error
		// Check if schemaURL is a local file or a URL
		if strings.HasPrefix(params.SchemaURL, "http://") || strings.HasPrefix(params.SchemaURL, "https://") {
			// Fetch from URL
			params.RawBytes, err = getSchemaURL(params.SchemaURL)
			if err != nil {
				params.Error = fmt.Errorf("failed to fetch schema from URL: %w", err)
				return params
			}
		} else {
			params.RawBytes, err = os.ReadFile(params.SchemaURL)
			if err != nil {
				params.Error = fmt.Errorf("failed to load schema: %w", err)
				return params
			}
		}
	}

	return params
}

// Base64Decode decodes a base64 string to bytes
func Base64Decode(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// ServeHTTP implements the http.Handler interface.
func (s *SSEServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	// Use exact path matching rather than Contains
	ssePath := s.CompleteSsePath()
	if ssePath != "" && path == ssePath {
		// Parse request parameters
		params := s.parseRequestParams(r)
		if params.Error != nil {
			http.Error(w, fmt.Sprintf("Failed to parse request parameters: %v", params.Error), http.StatusInternalServerError)
			return
		}

		var mcpServer *server.MCPServer

		// First, try with our custom parser
		var parser OpenAPIParser
		var parseErr error

		// Check if it looks like YAML or JSON
		if isYAML(params.RawBytes) {
			parser, parseErr = ParseOpenAPIFromYAML(params.RawBytes)
		} else {
			parser, parseErr = ParseOpenAPIFromJSON(params.RawBytes)
		}
		if parseErr != nil {
			http.Error(w, fmt.Sprintf("Failed to parse OpenAPI schema: %v", parseErr), http.StatusInternalServerError)
			return
		}

		// Apply filters if present
		if len(params.Filters) > 0 {
			// Create a filtered parser that wraps the original parser
			parser = &FilteredOpenAPIParser{
				BaseParser: parser,
				Filters:    params.Filters,
			}
		}

		var err error
		mcpServer, err = NewMCPFromCustomParser(params.BaseURL, params.Headers, parser)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to create MCP server: %v", err), http.StatusInternalServerError)
			return
		}

		s.handleSSE(mcpServer, w, r)
		return
	}
	messagePath := s.CompleteMessagePath()
	if messagePath != "" && path == messagePath {
		s.handleMessage(w, r)
		return
	}

	http.NotFound(w, r)
}

// FilteredOpenAPIParser is a wrapper around an OpenAPIParser that filters APIs
type FilteredOpenAPIParser struct {
	BaseParser OpenAPIParser
	Filters    []PathFilter
}

// Ensure FilteredOpenAPIParser implements the OpenAPIParser interface
var _ OpenAPIParser = (*FilteredOpenAPIParser)(nil)

// Servers delegates to the base parser
func (f *FilteredOpenAPIParser) Servers() []Server {
	return f.BaseParser.Servers()
}

// Info delegates to the base parser
func (f *FilteredOpenAPIParser) Info() APIInfo {
	return f.BaseParser.Info()
}

// APIs returns filtered APIs from the base parser
func (f *FilteredOpenAPIParser) APIs() []APIEndpoint {
	allAPIs := f.BaseParser.APIs()
	return ApplyFilters(allAPIs, f.Filters)
}

// isYAML checks if data looks like YAML
func isYAML(data []byte) bool {
	// Simple heuristic: check for common YAML indicators
	s := string(data)
	return strings.Contains(s, "---") ||
		strings.Contains(s, ":") && strings.Contains(s, "\n") ||
		strings.HasPrefix(strings.TrimSpace(s), "openapi:") ||
		strings.HasPrefix(strings.TrimSpace(s), "swagger:")
}

func createResponse(id interface{}, result interface{}) mcp.JSONRPCMessage {
	return mcp.JSONRPCResponse{
		JSONRPC: mcp.JSONRPC_VERSION,
		ID:      id,
		Result:  result,
	}
}

func createErrorResponse(
	id interface{},
	code int,
	message string,
) mcp.JSONRPCMessage {
	return mcp.JSONRPCError{
		JSONRPC: mcp.JSONRPC_VERSION,
		ID:      id,
		Error: struct {
			Code    int         `json:"code"`
			Message string      `json:"message"`
			Data    interface{} `json:"data,omitempty"`
		}{
			Code:    code,
			Message: message,
		},
	}
}

func getSchemaURL(schemaURL string) ([]byte, error) {
	if strings.HasPrefix(schemaURL, "http://") || strings.HasPrefix(schemaURL, "https://") {
		resp, httpErr := http.Get(schemaURL)
		if httpErr != nil {
			return nil, fmt.Errorf("failed to fetch schema from URL: %v", httpErr)
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(schemaURL)
}

// ShouldIncludePath determines if a path and method should be included based on filters
func ShouldIncludePath(path string, method string, filters []PathFilter) bool {
	// If no filters are defined, include everything
	if len(filters) == 0 {
		return true
	}

	// Track if we've seen any include filters
	hasIncludeFilters := false
	for _, filter := range filters {
		if !filter.Exclude {
			hasIncludeFilters = true
			break
		}
	}

	// Default behavior depends on whether we have any include filters
	// If we have include filters, default is to exclude unless explicitly included
	// If we only have exclude filters, default is to include unless explicitly excluded
	defaultInclude := !hasIncludeFilters

	// First apply include filters
	included := defaultInclude

	// Apply include filters first
	if hasIncludeFilters {
		included = false
		for _, filter := range filters {
			if !filter.Exclude && filter.MatchesPath(path) && filter.MatchesMethod(method) {
				included = true
				break
			}
		}
	}

	// Then apply exclude filters
	for _, filter := range filters {
		if filter.Exclude && filter.MatchesPath(path) && filter.MatchesMethod(method) {
			included = false
			break
		}
	}

	return included
}
