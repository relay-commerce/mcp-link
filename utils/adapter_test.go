package utils

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/require"
)

func TestBuildMCPProperties_NoLeakage_QueryAndPath(t *testing.T) {
	api := APIEndpoint{
		Parameters: []Parameter{
			{
				Name: "q",
				In:   "query",
				Schema: &Schema{
					Type:        "string",
					Description: "search term",
				},
			},
			{
				Name: "limit",
				In:   "query",
				Schema: &Schema{
					Type:    "integer",
					Default: 10,
					Format:  "int32",
				},
			},
			{
				Name: "id",
				In:   "path",
				Schema: &Schema{
					Type: "string",
				},
			},
		},
	}

	queryProps, pathProps, _ := BuildMCPProperties(api)

	// Parent maps must not have schema keywords
	for _, k := range []string{"type", "format", "default", "enum", "description", "items", "properties"} {
		require.NotContains(t, queryProps, k, "query parent must not contain keyword %s", k)
		require.NotContains(t, pathProps, k, "path parent must not contain keyword %s", k)
	}

	// Each child must carry its own schema
	qChild := queryProps["q"].(map[string]interface{})
	require.Equal(t, "string", qChild["type"])
	require.Equal(t, "search term", qChild["description"])

	limitChild := queryProps["limit"].(map[string]interface{})
	require.Equal(t, "integer", limitChild["type"])
	require.Equal(t, "int32", limitChild["format"])
	require.Equal(t, 10, limitChild["default"])

	idChild := pathProps["id"].(map[string]interface{})
	require.Equal(t, "string", idChild["type"])
}

func TestBuildMCPProperties_NoLeakage_RequestBody(t *testing.T) {
	api := APIEndpoint{
		RequestBody: &RequestBody{
			Content: map[string]MediaType{
				"application/json": {
					Schema: &Schema{
						Type: "object",
						Properties: map[string]Schema{
							"name": {
								Type:        "string",
								Description: "user name",
							},
							"age": {
								Type:    "integer",
								Format:  "int32",
								Default: 0,
							},
						},
					},
				},
			},
		},
	}

	_, _, bodyProps := BuildMCPProperties(api)

	// Parent must not have keyword leakage
	for _, k := range []string{"type", "format", "default", "enum", "description", "items", "properties"} {
		require.NotContains(t, bodyProps, k, "body parent must not contain keyword %s", k)
	}

	nameChild := bodyProps["name"].(map[string]interface{})
	require.Equal(t, "string", nameChild["type"])
	require.Equal(t, "user name", nameChild["description"])

	ageChild := bodyProps["age"].(map[string]interface{})
	require.Equal(t, "integer", ageChild["type"])
	require.Equal(t, "int32", ageChild["format"])
	require.Equal(t, 0, ageChild["default"])
}

func TestBuildMCPProperties_JSONSchema2020Validation(t *testing.T) {
	api := APIEndpoint{
		Parameters: []Parameter{
			{Name: "q", In: "query", Schema: &Schema{Type: "string"}},
			{Name: "limit", In: "query", Schema: &Schema{Type: "integer", Format: "int32"}},
		},
		RequestBody: &RequestBody{Content: map[string]MediaType{
			"application/json": {Schema: &Schema{Type: "object", Properties: map[string]Schema{
				"name": {Type: "string"},
				"age":  {Type: "integer", Format: "int32"},
			}}}},
		},
	}

	queryProps, _, bodyProps := BuildMCPProperties(api)

	// Build minimal wrapper schemas for validation against draft 2020-12
	wrap := func(props map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{
			"$schema":    "https://json-schema.org/draft/2020-12/schema",
			"type":       "object",
			"properties": props,
		}
	}

	validate := func(schemaObj map[string]interface{}) error {
		data, err := json.Marshal(schemaObj)
		if err != nil {
			return err
		}
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource("inmem.json", io.NopCloser(bytes.NewReader(data))); err != nil {
			return err
		}
		_, err = compiler.Compile("inmem.json")
		return err
	}

	require.NoError(t, validate(wrap(queryProps)), "queryProps should be a valid JSON Schema object")
	require.NoError(t, validate(wrap(bodyProps)), "bodyProps should be a valid JSON Schema object")
}

func TestBuildToolName_WithOperationID_NoPrefix(t *testing.T) {
	api := APIEndpoint{
		Path:        "/users/{id}",
		Method:      "GET",
		OperationID: "getUser",
	}

	name := buildToolName(api, "")
	require.Equal(t, "getUser", name)
}

func TestBuildToolName_WithOperationID_WithPrefix(t *testing.T) {
	api := APIEndpoint{
		Path:        "/users/{id}",
		Method:      "GET",
		OperationID: "getUser",
	}

	name := buildToolName(api, "myapi")
	require.Equal(t, "myapi_getUser", name)
}

func TestBuildToolName_NoOperationID_NoPrefix(t *testing.T) {
	api := APIEndpoint{
		Path:   "/users/{id}",
		Method: "GET",
	}

	name := buildToolName(api, "")
	require.Equal(t, "get_users_id", name)
}

func TestBuildToolName_NoOperationID_WithPrefix(t *testing.T) {
	api := APIEndpoint{
		Path:   "/users/{id}",
		Method: "POST",
	}

	name := buildToolName(api, "shop")
	require.Equal(t, "shop_post_users_id", name)
}

func TestBuildToolName_ComplexOperationID(t *testing.T) {
	api := APIEndpoint{
		Path:        "/store_data/store_data",
		Method:      "GET",
		OperationID: "getStoreData",
	}

	// Without prefix - should use operationId directly (case preserved)
	name := buildToolName(api, "")
	require.Equal(t, "getStoreData", name)

	// With prefix
	nameWithPrefix := buildToolName(api, "sr")
	require.Equal(t, "sr_getStoreData", nameWithPrefix)
}

func TestBuildToolName_SpecialCharactersInPath(t *testing.T) {
	api := APIEndpoint{
		Path:   "/api/v1/users/{user_id}/orders/{order_id}",
		Method: "DELETE",
	}

	name := buildToolName(api, "")
	require.Equal(t, "delete_api_v1_users_user_id_orders_order_id", name)
}

func TestBuildToolName_PrefixWithSpecialChars(t *testing.T) {
	api := APIEndpoint{
		Path:        "/test",
		Method:      "GET",
		OperationID: "testOp",
	}

	// Prefix with special characters should be sanitized, case preserved
	name := buildToolName(api, "my-api")
	require.Equal(t, "my_api_testOp", name)
}

func TestBuildMCPProperties_DescriptionPriority(t *testing.T) {
	api := APIEndpoint{
		Parameters: []Parameter{
			{
				Name:        "id",
				In:          "path",
				Description: "The unique identifier of the mailing.",
				Schema: &Schema{
					Type: "string",
				},
			},
			{
				Name:        "format",
				In:          "query",
				Description: "Output format for the response.",
				Schema: &Schema{
					Type:        "string",
					Description: "A string value.",
				},
			},
			{
				Name: "limit",
				In:   "query",
				Schema: &Schema{
					Type:        "integer",
					Description: "Maximum number of results.",
				},
			},
		},
	}

	queryProps, pathProps, _ := BuildMCPProperties(api)

	// Path param: parameter-level description should be used (schema has none)
	idChild := pathProps["id"].(map[string]interface{})
	require.Equal(t, "string", idChild["type"])
	require.Equal(t, "The unique identifier of the mailing.", idChild["description"])

	// Query param: parameter-level description takes priority over schema-level
	formatChild := queryProps["format"].(map[string]interface{})
	require.Equal(t, "string", formatChild["type"])
	require.Equal(t, "Output format for the response.", formatChild["description"])

	// Query param: schema-level description used as fallback when parameter-level is empty
	limitChild := queryProps["limit"].(map[string]interface{})
	require.Equal(t, "integer", limitChild["type"])
	require.Equal(t, "Maximum number of results.", limitChild["description"])
}

func TestJoinWithAnd(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		expected string
	}{
		{
			name:     "empty",
			items:    []string{},
			expected: "",
		},
		{
			name:     "single item",
			items:    []string{"path parameters in 'pathNames'"},
			expected: "path parameters in 'pathNames'",
		},
		{
			name:     "two items",
			items:    []string{"path parameters in 'pathNames'", "query parameters in 'searchParams'"},
			expected: "path parameters in 'pathNames' and query parameters in 'searchParams'",
		},
		{
			name:     "three items",
			items:    []string{"path parameters in 'pathNames'", "query parameters in 'searchParams'", "request body in 'requestBody'"},
			expected: "path parameters in 'pathNames', query parameters in 'searchParams', and request body in 'requestBody'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := joinWithAnd(tt.items)
			require.Equal(t, tt.expected, result)
		})
	}
}
