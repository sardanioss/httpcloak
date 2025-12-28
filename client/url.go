package client

import (
	"net/url"
	"sort"
	"strings"
)

// URLBuilder helps build URLs with query parameters
type URLBuilder struct {
	base   string
	params url.Values
}

// NewURLBuilder creates a new URLBuilder from a base URL
func NewURLBuilder(baseURL string) *URLBuilder {
	return &URLBuilder{
		base:   baseURL,
		params: make(url.Values),
	}
}

// Param adds a single query parameter
func (b *URLBuilder) Param(key, value string) *URLBuilder {
	b.params.Set(key, value)
	return b
}

// Params adds multiple query parameters from a map
func (b *URLBuilder) Params(params map[string]string) *URLBuilder {
	for key, value := range params {
		b.params.Set(key, value)
	}
	return b
}

// AddParam adds a query parameter (allows multiple values for same key)
func (b *URLBuilder) AddParam(key, value string) *URLBuilder {
	b.params.Add(key, value)
	return b
}

// Build builds the final URL string
func (b *URLBuilder) Build() string {
	if len(b.params) == 0 {
		return b.base
	}

	// Parse base URL to handle existing query params
	parsed, err := url.Parse(b.base)
	if err != nil {
		// If parse fails, just append params
		return b.base + "?" + b.params.Encode()
	}

	// Merge existing params with new params
	existingParams := parsed.Query()
	for key, values := range b.params {
		for _, value := range values {
			existingParams.Add(key, value)
		}
	}

	parsed.RawQuery = existingParams.Encode()
	return parsed.String()
}

// BuildSorted builds the final URL with sorted query parameters
// Useful for consistent URL generation (e.g., for caching)
func (b *URLBuilder) BuildSorted() string {
	if len(b.params) == 0 {
		return b.base
	}

	parsed, err := url.Parse(b.base)
	if err != nil {
		return b.base + "?" + sortedEncode(b.params)
	}

	existingParams := parsed.Query()
	for key, values := range b.params {
		for _, value := range values {
			existingParams.Add(key, value)
		}
	}

	parsed.RawQuery = sortedEncode(existingParams)
	return parsed.String()
}

// sortedEncode encodes url.Values with sorted keys
func sortedEncode(v url.Values) string {
	if len(v) == 0 {
		return ""
	}

	keys := make([]string, 0, len(v))
	for key := range v {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, key := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		values := v[key]
		for j, value := range values {
			if j > 0 {
				sb.WriteByte('&')
			}
			sb.WriteString(url.QueryEscape(key))
			sb.WriteByte('=')
			sb.WriteString(url.QueryEscape(value))
		}
	}
	return sb.String()
}

// EncodeParams encodes a map of parameters to a query string
func EncodeParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}

	values := make(url.Values)
	for key, value := range params {
		values.Set(key, value)
	}
	return values.Encode()
}

// DecodeParams decodes a query string to a map of parameters
func DecodeParams(query string) (map[string]string, error) {
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}

	params := make(map[string]string)
	for key, vals := range values {
		if len(vals) > 0 {
			params[key] = vals[0]
		}
	}
	return params, nil
}

// JoinURL joins a base URL with a path
func JoinURL(base, path string) string {
	if path == "" {
		return base
	}

	// Handle absolute URLs
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	// Parse base URL
	parsed, err := url.Parse(base)
	if err != nil {
		return base + "/" + strings.TrimPrefix(path, "/")
	}

	// Handle protocol-relative URLs
	if strings.HasPrefix(path, "//") {
		return parsed.Scheme + ":" + path
	}

	// Handle root-relative URLs
	if strings.HasPrefix(path, "/") {
		parsed.Path = path
		parsed.RawQuery = ""
		return parsed.String()
	}

	// Handle relative URLs
	if !strings.HasSuffix(parsed.Path, "/") {
		// Remove last path segment
		lastSlash := strings.LastIndex(parsed.Path, "/")
		if lastSlash >= 0 {
			parsed.Path = parsed.Path[:lastSlash+1]
		} else {
			parsed.Path = "/"
		}
	}
	parsed.Path += path
	parsed.RawQuery = ""

	return parsed.String()
}
