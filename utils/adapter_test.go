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

// no-op
