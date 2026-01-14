package utils

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jsref"
	"gopkg.in/yaml.v3"
)

// OpenAPIParser provides a simple interface for parsing OpenAPI specifications
type OpenAPIParser interface {
	// Info returns basic information about the API
	Servers() []Server
	Info() APIInfo
	// APIs returns information about all API endpoints
	APIs() []APIEndpoint
}

// Server represents a server in the OpenAPI specification
type Server struct {
	URL         string `json:"url,omitempty"`
	Description string `json:"description,omitempty"`
}

// APIInfo contains basic information about the API
type APIInfo struct {
	Title       string `json:"title,omitempty"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
}

// APIEndpoint represents a single API endpoint
type APIEndpoint struct {
	Path        string              `json:"path,omitempty"`
	Method      string              `json:"method,omitempty"`
	Summary     string              `json:"summary,omitempty"`
	Description string              `json:"description,omitempty"`
	OperationID string              `json:"operationId,omitempty"`
	Parameters  []Parameter         `json:"parameters,omitempty"`
	RequestBody *RequestBody        `json:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses,omitempty"`
}

// Parameter represents an API parameter
type Parameter struct {
	Name        string  `json:"name,omitempty"`
	In          string  `json:"in,omitempty"`
	Required    bool    `json:"required,omitempty"`
	Description string  `json:"description,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
}

// RequestBody represents the request body of an API endpoint
type RequestBody struct {
	Required bool                 `json:"required,omitempty"`
	Content  map[string]MediaType `json:"content,omitempty"`
}

// MediaType represents a media type of a request or response
type MediaType struct {
	Schema *Schema `json:"schema,omitempty"`
}

// Response represents an API response
type Response struct {
	Description string               `json:"description,omitempty"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

// Schema represents a JSON schema
type Schema struct {
	Type        string            `json:"type,omitempty"`
	Format      string            `json:"format,omitempty"`
	Description string            `json:"description,omitempty"`
	Default     interface{}       `json:"default,omitempty"`
	Enum        []interface{}     `json:"enum,omitempty"`
	Properties  map[string]Schema `json:"properties,omitempty"`
	Items       *Schema           `json:"items,omitempty"`
	Required    []string          `json:"required,omitempty"`
	Ref         string   `json:"$ref,omitempty"`
	OneOf       []Schema `json:"oneOf,omitempty"`
	AnyOf       []Schema `json:"anyOf,omitempty"`
	AllOf       []Schema `json:"allOf,omitempty"`
}

// SimpleOpenAPIParser is a simple parser for OpenAPI specifications
type SimpleOpenAPIParser struct {
	document map[string]interface{}
}

// NewSimpleOpenAPIParser creates a new OpenAPI parser
func NewSimpleOpenAPIParser(data []byte) (*SimpleOpenAPIParser, error) {
	jsonString := string(data)

	// Parse JSON into interface{}
	var v interface{}
	if err := json.Unmarshal([]byte(jsonString), &v); err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Create a new resolver
	resolver := jsref.New()

	resolved, err := resolver.Resolve(v, "#", jsref.WithRecursiveResolution(false))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve references: %w", err)
	}

	resolvedMap, ok := resolved.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to convert resolved to map[string]interface{}")
	}
	parser := &SimpleOpenAPIParser{
		document: resolvedMap,
	}

	return parser, nil
}

// Servers returns the servers in the OpenAPI specification
func (p *SimpleOpenAPIParser) Servers() []Server {
	servers := []Server{}

	if serversObj, ok := p.document["servers"].([]interface{}); ok {
		for _, server := range serversObj {
			serverObj, ok := server.(map[string]interface{})
			if !ok {
				continue
			}

			server := Server{}

			if url, ok := serverObj["url"].(string); ok {
				server.URL = url
			}

			if description, ok := serverObj["description"].(string); ok {
				server.Description = description
			}

			servers = append(servers, server)
		}
	}

	return servers
}

// Info returns basic information about the API
func (p *SimpleOpenAPIParser) Info() APIInfo {
	info := APIInfo{}

	if infoObj, ok := p.document["info"].(map[string]interface{}); ok {
		if title, ok := infoObj["title"].(string); ok {
			info.Title = title
		}

		if version, ok := infoObj["version"].(string); ok {
			info.Version = version
		}

		if description, ok := infoObj["description"].(string); ok {
			info.Description = description
		}
	}

	return info
}

// APIs returns information about all API endpoints
func (p *SimpleOpenAPIParser) APIs() []APIEndpoint {
	var endpoints []APIEndpoint

	paths, ok := p.document["paths"].(map[string]interface{})
	if !ok {
		return endpoints
	}

	for path, pathItem := range paths {
		pathItemObj, ok := pathItem.(map[string]interface{})
		if !ok {
			continue
		}

		for method, operation := range pathItemObj {
			// Skip non-HTTP method fields
			if !isHTTPMethod(method) {
				continue
			}

			operationObj, ok := operation.(map[string]interface{})
			if !ok {
				continue
			}

			endpoint := APIEndpoint{
				Path:      path,
				Method:    strings.ToUpper(method),
				Responses: make(map[string]Response),
			}

			if summary, ok := operationObj["summary"].(string); ok {
				endpoint.Summary = summary
			}

			if description, ok := operationObj["description"].(string); ok {
				endpoint.Description = description
			}

			if operationId, ok := operationObj["operationId"].(string); ok {
				endpoint.OperationID = operationId
			}

			// Parse parameters
			if parameters, ok := operationObj["parameters"].([]interface{}); ok {
				for _, param := range parameters {
					paramObj, ok := param.(map[string]interface{})
					if !ok {
						continue
					}

					parameter := Parameter{}

					if name, ok := paramObj["name"].(string); ok {
						parameter.Name = name
					}

					if in, ok := paramObj["in"].(string); ok {
						parameter.In = in
					}

					if required, ok := paramObj["required"].(bool); ok {
						parameter.Required = required
					}

					if description, ok := paramObj["description"].(string); ok {
						parameter.Description = description
					}

					if schemaObj, ok := paramObj["schema"].(map[string]interface{}); ok {
						schema := p.parseSchema(schemaObj)
						parameter.Schema = &schema
					}

					endpoint.Parameters = append(endpoint.Parameters, parameter)
				}
			}

			// Parse request body
			if requestBodyObj, ok := operationObj["requestBody"].(map[string]interface{}); ok {
				requestBody := RequestBody{
					Content: make(map[string]MediaType),
				}

				if required, ok := requestBodyObj["required"].(bool); ok {
					requestBody.Required = required
				}

				if contentObj, ok := requestBodyObj["content"].(map[string]interface{}); ok {
					for mediaTypeName, mediaTypeObj := range contentObj {
						if mediaTypeMap, ok := mediaTypeObj.(map[string]interface{}); ok {
							mediaType := MediaType{}

							if schemaObj, ok := mediaTypeMap["schema"].(map[string]interface{}); ok {
								schema := p.parseSchema(schemaObj)
								mediaType.Schema = &schema
							}

							requestBody.Content[mediaTypeName] = mediaType
						}
					}
				}

				endpoint.RequestBody = &requestBody
			}

			// Parse responses
			if responsesObj, ok := operationObj["responses"].(map[string]interface{}); ok {
				for statusCode, responseObj := range responsesObj {
					if responseMap, ok := responseObj.(map[string]interface{}); ok {
						response := Response{
							Content: make(map[string]MediaType),
						}

						if description, ok := responseMap["description"].(string); ok {
							response.Description = description
						}

						if contentObj, ok := responseMap["content"].(map[string]interface{}); ok {
							for mediaTypeName, mediaTypeObj := range contentObj {
								if mediaTypeMap, ok := mediaTypeObj.(map[string]interface{}); ok {
									mediaType := MediaType{}

									if schemaObj, ok := mediaTypeMap["schema"].(map[string]interface{}); ok {
										schema := p.parseSchema(schemaObj)
										mediaType.Schema = &schema
									}

									response.Content[mediaTypeName] = mediaType
								}
							}
						}

						endpoint.Responses[statusCode] = response
					}
				}
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// maxSchemaDepth is the maximum depth for parsing nested schemas
// This prevents stack overflow from recursive schemas
const maxSchemaDepth = 5

// parseSchema parses a JSON schema object (public wrapper)
func (p *SimpleOpenAPIParser) parseSchema(schemaObj map[string]interface{}) Schema {
	return p.parseSchemaWithDepth(schemaObj, 0)
}

// parseSchemaWithDepth parses a JSON schema object with depth tracking
func (p *SimpleOpenAPIParser) parseSchemaWithDepth(schemaObj map[string]interface{}, depth int) Schema {
	schema := Schema{
		Properties: make(map[string]Schema),
	}

	// Stop parsing if max depth exceeded
	if depth > maxSchemaDepth {
		schema.Description = "(schema truncated - max depth exceeded)"
		return schema
	}

	// Handle $ref - resolve reference from components/schemas
	if ref, ok := schemaObj["$ref"].(string); ok {
		resolved := p.resolveRef(ref)
		if resolved != nil {
			return p.parseSchemaWithDepth(resolved, depth+1)
		}
		// If ref couldn't be resolved, note it in description
		schema.Ref = ref
		schema.Description = fmt.Sprintf("(unresolved reference: %s)", ref)
		return schema
	}

	if t, ok := schemaObj["type"].(string); ok {
		schema.Type = t
	}

	if format, ok := schemaObj["format"].(string); ok {
		schema.Format = format
	}

	if description, ok := schemaObj["description"].(string); ok {
		schema.Description = description
	}

	if defaultValue, ok := schemaObj["default"]; ok {
		schema.Default = defaultValue
	}

	if enum, ok := schemaObj["enum"].([]interface{}); ok {
		schema.Enum = enum
	}

	if required, ok := schemaObj["required"].([]interface{}); ok {
		for _, req := range required {
			if reqStr, ok := req.(string); ok {
				schema.Required = append(schema.Required, reqStr)
			}
		}
	}

	// Handle properties
	if properties, ok := schemaObj["properties"].(map[string]interface{}); ok {
		for propName, propObj := range properties {
			if propMap, ok := propObj.(map[string]interface{}); ok {
				propSchema := p.parseSchemaWithDepth(propMap, depth+1)
				schema.Properties[propName] = propSchema
			}
		}
	}

	// Handle items for array type
	if items, ok := schemaObj["items"].(map[string]interface{}); ok {
		itemsSchema := p.parseSchemaWithDepth(items, depth+1)
		schema.Items = &itemsSchema
	}

	// Handle oneOf - parse each variant schema
	if oneOf, ok := schemaObj["oneOf"].([]interface{}); ok {
		for _, variant := range oneOf {
			if variantMap, ok := variant.(map[string]interface{}); ok {
				variantSchema := p.parseSchemaWithDepth(variantMap, depth+1)
				schema.OneOf = append(schema.OneOf, variantSchema)
			}
		}
	}

	// Handle anyOf - parse each variant schema
	if anyOf, ok := schemaObj["anyOf"].([]interface{}); ok {
		for _, variant := range anyOf {
			if variantMap, ok := variant.(map[string]interface{}); ok {
				variantSchema := p.parseSchemaWithDepth(variantMap, depth+1)
				schema.AnyOf = append(schema.AnyOf, variantSchema)
			}
		}
	}

	// Handle allOf - parse each variant schema
	if allOf, ok := schemaObj["allOf"].([]interface{}); ok {
		for _, variant := range allOf {
			if variantMap, ok := variant.(map[string]interface{}); ok {
				variantSchema := p.parseSchemaWithDepth(variantMap, depth+1)
				schema.AllOf = append(schema.AllOf, variantSchema)
			}
		}
	}

	return schema
}

func isHTTPMethod(method string) bool {
	method = strings.ToLower(method)
	return method == "get" || method == "post" || method == "put" ||
		method == "delete" || method == "options" || method == "head" ||
		method == "patch" || method == "trace"
}

// resolveRef resolves a $ref pointer to the actual schema object
// Supports refs like "#/components/schemas/MySchema"
func (p *SimpleOpenAPIParser) resolveRef(ref string) map[string]interface{} {
	if !strings.HasPrefix(ref, "#/") {
		return nil // Only support local references
	}

	// Split the path: "#/components/schemas/MySchema" -> ["components", "schemas", "MySchema"]
	parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")

	current := p.document
	for _, part := range parts {
		if current == nil {
			return nil
		}
		next, ok := current[part]
		if !ok {
			return nil
		}
		current, ok = next.(map[string]interface{})
		if !ok {
			return nil
		}
	}

	return current
}

// ParseOpenAPIFromYAML parses OpenAPI specification from YAML format
func ParseOpenAPIFromYAML(data []byte) (OpenAPIParser, error) {
	// Convert YAML to JSON for consistent processing
	var jsonData []byte
	var yamlObj interface{}

	// Unmarshal YAML to an interface
	if err := yaml.Unmarshal(data, &yamlObj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	// Marshal the interface to JSON
	jsonData, err := json.Marshal(yamlObj)
	if err != nil {
		return nil, fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	// Use the JSON data for parsing
	data = jsonData
	parser, err := NewSimpleOpenAPIParser(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI specification: %w", err)
	}
	return parser, nil
}

// ParseOpenAPIFromJSON parses an OpenAPI specification from JSON
func ParseOpenAPIFromJSON(data []byte) (OpenAPIParser, error) {
	return NewSimpleOpenAPIParser(data)
}
