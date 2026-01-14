package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	jsref "github.com/lestrrat-go/jsref"
	"sigs.k8s.io/yaml"
)

func Test_ParseSchema_OneOf(t *testing.T) {
	// Test YAML with oneOf schema
	yamlData := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /blocks:
    post:
      operationId: createBlock
      summary: Create a block
      parameters:
        - name: block
          in: query
          schema:
            type: object
            properties:
              type:
                type: string
                enum: [text, image]
              fields:
                type: object
            oneOf:
              - properties:
                  type:
                    enum: [text]
                  fields:
                    type: object
                    properties:
                      title:
                        type: string
                        description: Title of text block
                      description_text:
                        type: string
                        description: Text content
              - properties:
                  type:
                    enum: [image]
                  fields:
                    type: object
                    properties:
                      image_source:
                        type: string
                        description: Image URL
                      alt_text:
                        type: string
                        description: Alt text
      responses:
        "200":
          description: Success
`)

	parser, err := ParseOpenAPIFromYAML(yamlData)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	apis := parser.APIs()
	if len(apis) != 1 {
		t.Fatalf("Expected 1 API endpoint, got %d", len(apis))
	}

	api := apis[0]
	if len(api.Parameters) != 1 {
		t.Fatalf("Expected 1 parameter, got %d", len(api.Parameters))
	}

	param := api.Parameters[0]
	if param.Schema == nil {
		t.Fatal("Expected parameter to have schema")
	}

	// Check that oneOf was parsed
	if len(param.Schema.OneOf) != 2 {
		t.Fatalf("Expected 2 oneOf variants, got %d", len(param.Schema.OneOf))
	}

	// Check first variant (text block)
	textVariant := param.Schema.OneOf[0]
	if textVariant.Properties == nil {
		t.Fatal("Expected text variant to have properties")
	}

	fieldsSchema, ok := textVariant.Properties["fields"]
	if !ok {
		t.Fatal("Expected text variant to have 'fields' property")
	}

	if fieldsSchema.Properties == nil {
		t.Fatal("Expected fields schema to have properties")
	}

	titleSchema, ok := fieldsSchema.Properties["title"]
	if !ok {
		t.Fatal("Expected fields to have 'title' property")
	}

	if titleSchema.Type != "string" {
		t.Errorf("Expected title type to be 'string', got '%s'", titleSchema.Type)
	}

	if titleSchema.Description != "Title of text block" {
		t.Errorf("Expected title description to be 'Title of text block', got '%s'", titleSchema.Description)
	}

	// Check second variant (image block)
	imageVariant := param.Schema.OneOf[1]
	imageFields, ok := imageVariant.Properties["fields"]
	if !ok {
		t.Fatal("Expected image variant to have 'fields' property")
	}

	imageSourceSchema, ok := imageFields.Properties["image_source"]
	if !ok {
		t.Fatal("Expected image fields to have 'image_source' property")
	}

	if imageSourceSchema.Description != "Image URL" {
		t.Errorf("Expected image_source description to be 'Image URL', got '%s'", imageSourceSchema.Description)
	}
}

func Test_ParseSchema_AnyOf(t *testing.T) {
	yamlData := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /test:
    get:
      operationId: test
      summary: Test
      parameters:
        - name: value
          in: query
          schema:
            anyOf:
              - type: string
              - type: integer
      responses:
        "200":
          description: Success
`)

	parser, err := ParseOpenAPIFromYAML(yamlData)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	apis := parser.APIs()
	param := apis[0].Parameters[0]

	if len(param.Schema.AnyOf) != 2 {
		t.Fatalf("Expected 2 anyOf variants, got %d", len(param.Schema.AnyOf))
	}

	if param.Schema.AnyOf[0].Type != "string" {
		t.Errorf("Expected first anyOf type to be 'string', got '%s'", param.Schema.AnyOf[0].Type)
	}

	if param.Schema.AnyOf[1].Type != "integer" {
		t.Errorf("Expected second anyOf type to be 'integer', got '%s'", param.Schema.AnyOf[1].Type)
	}
}

func Test_ParseSchema_AllOf(t *testing.T) {
	yamlData := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /test:
    get:
      operationId: test
      summary: Test
      parameters:
        - name: combined
          in: query
          schema:
            allOf:
              - type: object
                properties:
                  id:
                    type: integer
              - type: object
                properties:
                  name:
                    type: string
      responses:
        "200":
          description: Success
`)

	parser, err := ParseOpenAPIFromYAML(yamlData)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	apis := parser.APIs()
	param := apis[0].Parameters[0]

	if len(param.Schema.AllOf) != 2 {
		t.Fatalf("Expected 2 allOf variants, got %d", len(param.Schema.AllOf))
	}

	// Check first allOf has 'id' property
	if _, ok := param.Schema.AllOf[0].Properties["id"]; !ok {
		t.Error("Expected first allOf to have 'id' property")
	}

	// Check second allOf has 'name' property
	if _, ok := param.Schema.AllOf[1].Properties["name"]; !ok {
		t.Error("Expected second allOf to have 'name' property")
	}
}

func Test_ParseSchema_MaxDepth(t *testing.T) {
	// Create a deeply nested schema (deeper than maxSchemaDepth)
	yamlData := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /deep:
    get:
      operationId: testDeep
      summary: Test deep nesting
      parameters:
        - name: nested
          in: query
          schema:
            type: object
            properties:
              level1:
                type: object
                properties:
                  level2:
                    type: object
                    properties:
                      level3:
                        type: object
                        properties:
                          level4:
                            type: object
                            properties:
                              level5:
                                type: object
                                properties:
                                  level6:
                                    type: object
                                    properties:
                                      level7:
                                        type: object
                                        properties:
                                          level8:
                                            type: object
                                            properties:
                                              level9:
                                                type: object
                                                properties:
                                                  level10:
                                                    type: object
                                                    properties:
                                                      level11:
                                                        type: object
                                                        properties:
                                                          level12:
                                                            type: object
                                                            properties:
                                                              deepValue:
                                                                type: string
                                                                description: This should be truncated
      responses:
        "200":
          description: Success
`)

	parser, err := ParseOpenAPIFromYAML(yamlData)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	apis := parser.APIs()
	if len(apis) != 1 {
		t.Fatalf("Expected 1 API endpoint, got %d", len(apis))
	}

	param := apis[0].Parameters[0]
	if param.Schema == nil {
		t.Fatal("Expected parameter to have schema")
	}

	// Navigate to a deep level and verify parsing didn't crash
	// and that truncation message appears at some point
	current := param.Schema
	depth := 0
	foundTruncation := false

	for depth < 15 {
		if current.Description == "(schema truncated - max depth exceeded)" {
			foundTruncation = true
			break
		}

		// Try to go deeper via level properties
		levelKey := fmt.Sprintf("level%d", depth+1)
		if next, ok := current.Properties[levelKey]; ok {
			current = &next
			depth++
		} else {
			break
		}
	}

	if !foundTruncation {
		t.Errorf("Expected truncation message at depth > %d, but reached depth %d without finding it", maxSchemaDepth, depth)
	}
}

func Test_ParseSchema_RefResolution(t *testing.T) {
	// Test $ref resolution with a recursive schema
	yamlData := []byte(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /tree:
    post:
      operationId: createTree
      summary: Create a tree
      parameters:
        - name: node
          in: query
          schema:
            $ref: '#/components/schemas/TreeNode'
      responses:
        "200":
          description: Success
components:
  schemas:
    TreeNode:
      type: object
      properties:
        value:
          type: string
          description: Node value
        children:
          type: array
          description: Child nodes
          items:
            $ref: '#/components/schemas/TreeNode'
`)

	parser, err := ParseOpenAPIFromYAML(yamlData)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	apis := parser.APIs()
	if len(apis) != 1 {
		t.Fatalf("Expected 1 API endpoint, got %d", len(apis))
	}

	param := apis[0].Parameters[0]
	if param.Schema == nil {
		t.Fatal("Expected parameter to have schema")
	}

	// Check that the $ref was resolved - should have type "object"
	if param.Schema.Type != "object" {
		t.Errorf("Expected schema type 'object' (resolved from ref), got '%s'", param.Schema.Type)
	}

	// Check that properties were resolved
	valueSchema, ok := param.Schema.Properties["value"]
	if !ok {
		t.Fatal("Expected resolved schema to have 'value' property")
	}

	if valueSchema.Type != "string" {
		t.Errorf("Expected value type to be 'string', got '%s'", valueSchema.Type)
	}

	if valueSchema.Description != "Node value" {
		t.Errorf("Expected value description to be 'Node value', got '%s'", valueSchema.Description)
	}

	// Check children array with recursive ref
	childrenSchema, ok := param.Schema.Properties["children"]
	if !ok {
		t.Fatal("Expected resolved schema to have 'children' property")
	}

	if childrenSchema.Type != "array" {
		t.Errorf("Expected children type to be 'array', got '%s'", childrenSchema.Type)
	}

	// Children items should also be resolved (up to max depth)
	if childrenSchema.Items == nil {
		t.Fatal("Expected children to have items schema")
	}

	// The recursive ref should be resolved
	if childrenSchema.Items.Type != "object" {
		t.Errorf("Expected children items type to be 'object', got '%s'", childrenSchema.Items.Type)
	}
}

func Test_Schema_JSON_OmitsEmptyFields(t *testing.T) {
	schema := Schema{
		Type:        "string",
		Description: "A test field",
		// Ref, OneOf, AnyOf, AllOf, etc. are all empty
	}

	output, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("Failed to marshal schema: %v", err)
	}

	jsonStr := string(output)

	// These empty fields should not appear in output
	unwantedFields := []string{`"$ref"`, `"Ref"`, `"oneOf"`, `"anyOf"`, `"allOf"`, `"properties"`, `"items"`}
	for _, field := range unwantedFields {
		if strings.Contains(jsonStr, field) {
			t.Errorf("JSON output should not contain %s when empty, got: %s", field, jsonStr)
		}
	}
}

func Test_ParseYamlToJson(t *testing.T) {
	b, err := os.ReadFile("../examples/fal-text2image.yaml")
	if err != nil {
		t.Fatalf("Error reading YAML file: %v", err)
	}

	jsonString, err := yaml.YAMLToJSON(b)
	if err != nil {
		t.Fatalf("Error converting YAML to JSON: %v", err)
	}

	// Parse JSON into interface{}
	var v interface{}
	if err := json.Unmarshal(jsonString, &v); err != nil {
		t.Fatalf("Error unmarshaling JSON: %v", err)
	}

	// Create a new resolver
	resolver := jsref.New()

	// Resolve all references recursively
	resolved, err := resolver.Resolve(v, "#", jsref.WithRecursiveResolution(true))
	if err != nil {
		t.Fatalf("Error resolving references: %v", err)
	}

	// Convert back to JSON for OpenAPI processing
	resolvedJSON, err := json.Marshal(resolved)
	if err != nil {
		t.Fatalf("Error marshaling resolved JSON: %v", err)
	}

	// Load into OpenAPI document
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	doc, err := loader.LoadFromData(resolvedJSON)
	if err != nil {
		t.Fatalf("Error loading JSON: %v", err)
	}

	// Validate the document
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("Error validating JSON: %v", err)
	}

	// Format the final result
	prettyJSON, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("Error marshaling JSON: %v", err)
	}

	fmt.Println(string(prettyJSON))
}
