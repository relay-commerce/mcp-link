package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func sanitizeToolName(name string) string {
	// Replace special characters (preserving case)
	s := name
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "{", "")
	s = strings.ReplaceAll(s, "}", "")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "?", "")
	s = strings.ReplaceAll(s, "&", "and")
	s = strings.ReplaceAll(s, "=", "_eq_")
	s = strings.ReplaceAll(s, "%", "_pct_")

	// Remove consecutive underscores
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}

	// Remove trailing underscore
	s = strings.TrimSuffix(s, "_")

	// Remove leading underscore
	s = strings.TrimPrefix(s, "_")

	// Ensure the name is not empty
	if s == "" {
		return "unnamed_tool"
	}

	return s
}

// joinWithAnd joins strings with commas and "and" for proper grammar
// e.g., ["A"] -> "A", ["A", "B"] -> "A and B", ["A", "B", "C"] -> "A, B, and C"
func joinWithAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
	}
}

// buildToolName creates a tool name from the API endpoint
// Priority: operationId if available, otherwise method_path
// Prefix is prepended if provided
func buildToolName(api APIEndpoint, toolPrefix string) string {
	var name string

	// Use operationId if available, fallback to method_path
	if api.OperationID != "" {
		name = api.OperationID
	} else {
		name = fmt.Sprintf("%s_%s", strings.ToLower(api.Method), api.Path)
	}

	// Add prefix if provided
	if toolPrefix != "" {
		name = fmt.Sprintf("%s_%s", toolPrefix, name)
	}

	return sanitizeToolName(name)
}

func NewToolHandler(method string, url string, extraHeaders map[string]string) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters from the request
		params := request.Params.Arguments

		// Create maps for different parameter types
		pathParams := make(map[string]interface{})
		queryParams := make(map[string]interface{})
		bodyParams := make(map[string]interface{})

		// Extract specific parameter groups
		if pathParamsMap, ok := params["pathNames"].(map[string]interface{}); ok {
			pathParams = pathParamsMap
		}

		if urlParamsMap, ok := params["searchParams"].(map[string]interface{}); ok {
			queryParams = urlParamsMap
		}

		if requestBodyMap, ok := params["requestBody"].(map[string]interface{}); ok {
			bodyParams = requestBodyMap
		}

		// If structured params aren't found, use flat params for backward compatibility
		if len(pathParams) == 0 && len(queryParams) == 0 && len(bodyParams) == 0 {
			// Process all params without structured separation (legacy approach)
			for paramName, paramValue := range params {
				placeholder := fmt.Sprintf("{%s}", paramName)
				if strings.Contains(url, placeholder) {
					pathParams[paramName] = paramValue
				} else {
					// Put in body by default
					bodyParams[paramName] = paramValue
				}
			}
		}

		// Create a copy of the URL for path parameter substitution
		finalURL := url

		// Process URL path parameters - replace {param_name} with the value from pathParams
		for paramName, paramValue := range pathParams {
			placeholder := fmt.Sprintf("{%s}", paramName)
			if strings.Contains(finalURL, placeholder) {
				// Convert the param value to string
				var strValue string
				switch v := paramValue.(type) {
				case string:
					strValue = v
				case nil:
					// Use empty string for nil path parameters
					strValue = ""
				default:
					// Convert other types to string
					strValue = fmt.Sprintf("%v", v)
				}

				// Replace the placeholder in the URL
				finalURL = strings.ReplaceAll(finalURL, placeholder, strValue)
			}
		}
		// Add query parameters to the URL
		if len(queryParams) > 0 {
			// Parse the URL to add query parameters properly
			parsedURL, err := neturl.Parse(finalURL)
			if err != nil {
				return mcp.NewToolResultText(fmt.Sprintf("Error parsing URL: %v", err)), nil
			}

			// Get existing query values or create new ones
			q := parsedURL.Query()

			// Add all query parameters
			for paramName, paramValue := range queryParams {
				// Convert the param value to string
				var strValue string
				switch v := paramValue.(type) {
				case string:
					strValue = v
				case nil:
					continue
				default:
					// Convert other types to string
					strValue = fmt.Sprintf("%v", v)
				}

				q.Add(paramName, strValue)
			}

			// Set the updated query string back to the URL
			parsedURL.RawQuery = q.Encode()
			finalURL = parsedURL.String()
		}

		// Convert body parameters to JSON for the HTTP request body
		var reqBody io.Reader = nil
		if len(bodyParams) > 0 {
			jsonParams, err := json.Marshal(bodyParams)
			if err != nil {
				return mcp.NewToolResultText(fmt.Sprintf("Error marshaling body parameters: %v", err)), nil
			}
			reqBody = bytes.NewBuffer(jsonParams)
		}

		// Create HTTP request with the processed URL
		req, err := http.NewRequestWithContext(ctx, method, finalURL, reqBody)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Error creating request: %v", err)), nil
		}

		// Set headers
		if reqBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for key, value := range extraHeaders {
			req.Header.Set(key, value)
		}

		// Execute the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Error executing request: %v", err)), nil
		}
		defer resp.Body.Close()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("Error reading response: %v", err)), nil
		}

		// TODO: handle image response
		// if strings.HasPrefix(resp.Header.Get("Content-Type"), "image/") {
		// return mcp.NewToolResultImage("", base64.StdEncoding.EncodeToString(body), resp.Header.Get("Content-Type")), nil
		// }

		if resp.StatusCode >= 400 {
			return mcp.NewToolResultText(fmt.Sprintf("[HTTP %d]\n%s", resp.StatusCode, string(body))), nil
		}
		return mcp.NewToolResultText(string(body)), nil
	}
}

// NewMCPFromCustomParser creates an MCP server from our custom OpenAPIParser
func NewMCPFromCustomParser(baseURL string, extraHeaders map[string]string, parser OpenAPIParser, toolPrefix string) (*server.MCPServer, error) {
	// Create a new MCP server
	apiInfo := parser.Info()
	serverName := sanitizeToolName(apiInfo.Title)
	if serverName == "" {
		serverName = "mcp_server"
	}

	s := server.NewMCPServer(
		serverName,
		apiInfo.Version,
		server.WithResourceCapabilities(true, true),
		server.WithLogging(),
	)

	// Add all API endpoints as tools
	for _, api := range parser.APIs() {
		// Create tool name using operationId or method_path with optional prefix
		name := buildToolName(api, toolPrefix)

		// Add parameters
		query_props, path_props, body_props := BuildMCPProperties(api)

		// Build description with input structure hints
		description := api.OperationID + " " + api.Summary + " " + api.Description
		var inputHints []string
		if len(path_props) > 0 {
			inputHints = append(inputHints, "path parameters in 'pathNames'")
		}
		if len(query_props) > 0 {
			inputHints = append(inputHints, "query parameters in 'searchParams'")
		}
		if len(body_props) > 0 {
			inputHints = append(inputHints, "request body in 'requestBody'")
		}
		if len(inputHints) > 0 {
			description += " Pass " + joinWithAnd(inputHints) + "."
		}

		// Define tool options
		opts := []mcp.ToolOption{
			mcp.WithDescription(description),
		}

		if len(query_props) > 0 {
			opts = append(opts, mcp.WithObject("searchParams", mcp.Description("url parameters for the tool"), mcp.Properties(query_props)))
		}
		if len(path_props) > 0 {
			opts = append(opts, mcp.WithObject("pathNames", mcp.Description("path parameters for the tool"), mcp.Properties(path_props)))
		}
		if len(body_props) > 0 {
			opts = append(opts, mcp.WithObject("requestBody", mcp.Description("request body for the tool"), mcp.Properties(body_props)))
		}

		// Create the tool and handler
		tool := mcp.NewTool(name, opts...)
		handler := NewToolHandler(api.Method, baseURL+api.Path, extraHeaders)

		// Add the tool to the server
		s.AddTool(tool, handler)
	}

	return s, nil
}
