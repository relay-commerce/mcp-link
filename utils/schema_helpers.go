package utils

// BuildMCPProperties constructs schema property maps for query, path and request body
// from an APIEndpoint. Each property's schema keywords are nested within the child
// map keyed by the property name, avoiding leakage into the parent map.
func BuildMCPProperties(api APIEndpoint) (map[string]interface{}, map[string]interface{}, map[string]interface{}) {
	queryProps := map[string]interface{}{}
	pathProps := map[string]interface{}{}
	bodyProps := map[string]interface{}{}

	for _, param := range api.Parameters {
		switch param.In {
		case "query":
			child := map[string]interface{}{}
			if param.Schema != nil {
				child["type"] = param.Schema.Type
				if param.Schema.Enum != nil {
					child["enum"] = param.Schema.Enum
				}
				if param.Schema.Format != "" {
					child["format"] = param.Schema.Format
				}
				if param.Schema.Default != nil {
					child["default"] = param.Schema.Default
				}
				if param.Schema.Description != "" {
					child["description"] = param.Schema.Description
				}
				if param.Schema.Items != nil {
					child["items"] = param.Schema.Items
				}
				if param.Schema.Properties != nil {
					child["properties"] = param.Schema.Properties
				}
			}
			queryProps[param.Name] = child
		case "path":
			child := map[string]interface{}{}
			if param.Schema != nil {
				child["type"] = param.Schema.Type
				if param.Schema.Enum != nil {
					child["enum"] = param.Schema.Enum
				}
				if param.Schema.Format != "" {
					child["format"] = param.Schema.Format
				}
				if param.Schema.Default != nil {
					child["default"] = param.Schema.Default
				}
				if param.Schema.Description != "" {
					child["description"] = param.Schema.Description
				}
				if param.Schema.Items != nil {
					child["items"] = param.Schema.Items
				}
			}
			pathProps[param.Name] = child
		}
	}

	if api.RequestBody != nil && len(api.RequestBody.Content) > 0 {
		for _, mediaType := range api.RequestBody.Content {
			if mediaType.Schema != nil && mediaType.Schema.Properties != nil {
				for propName, propSchema := range mediaType.Schema.Properties {
					child := map[string]interface{}{}
					child["type"] = propSchema.Type
					if propSchema.Enum != nil {
						child["enum"] = propSchema.Enum
					}
					if propSchema.Format != "" {
						child["format"] = propSchema.Format
					}
					if propSchema.Default != nil {
						child["default"] = propSchema.Default
					}
					if propSchema.Description != "" {
						child["description"] = propSchema.Description
					}
					if propSchema.Items != nil {
						child["items"] = propSchema.Items
					}
					if propSchema.Properties != nil {
						child["properties"] = propSchema.Properties
					}
					bodyProps[propName] = child
				}
			}
		}
	}

	return queryProps, pathProps, bodyProps
}
