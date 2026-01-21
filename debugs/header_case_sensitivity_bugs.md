# Header Case-Sensitivity Bugs

**Status: FIXED**

## Found Issues

### Bug #1: Request.GetHeader() lacks case-insensitivity (HIGH)
**File:** `client/client.go:442-447`

```go
func (r *Request) GetHeader(key string) string {
    if values := r.Headers[key]; len(values) > 0 {  // BUG: Not case-insensitive
        return values[0]
    }
    return ""
}
```

**Fix:** Use case-insensitive lookup like Response.GetHeader() does.

---

### Bug #2: Host header lookup case-sensitive (HIGH)
**File:** `client/client.go:1003-1004`

```go
if _, hasHost := req.Headers["Host"]; !hasHost {  // BUG: Case-sensitive!
    req.Headers["Host"] = []string{parsedURL.Hostname()}
}
```

If user sets `"host"` (lowercase), this adds duplicate `"Host"` header.

**Fix:** Use case-insensitive check.

---

### Bug #3: Accept header case-sensitive in applyModeHeaders (MEDIUM)
**File:** `client/client.go:1452-1457`

```go
if acceptValues, ok := req.Headers["Accept"]; ok && len(acceptValues) > 0 {
```

**Fix:** Use case-insensitive lookup.

---

### Bug #4: Accept header case-sensitive in applyCORSModeHeaders (MEDIUM)
**File:** `client/client.go:1587-1591`

```go
if acceptValues, ok := req.Headers["Accept"]; ok && len(acceptValues) > 0 {
```

**Fix:** Use case-insensitive lookup.

---

## Solution

Create a helper function for case-insensitive header lookup:

```go
// getHeaderCaseInsensitive retrieves a header value from a map case-insensitively.
// Returns the values and whether the header was found.
func getHeaderCaseInsensitive(headers map[string][]string, key string) ([]string, bool) {
    // Try exact match first (most common case)
    if values, ok := headers[key]; ok {
        return values, true
    }
    // Fall back to case-insensitive search
    keyLower := strings.ToLower(key)
    for k, v := range headers {
        if strings.ToLower(k) == keyLower {
            return v, true
        }
    }
    return nil, false
}
```

---

### Bug #5: Request.Headers missing auto-added headers (ADDED)
**File:** `client/client.go`

**Issue:** `req.Headers` only contained user-provided headers, not headers added by the library (User-Agent, Accept, Sec-Fetch-*, etc.)

**Fix:** After all headers are applied to httpReq (including hooks), copy them to req.Headers:
```go
for key, values := range httpReq.Header {
    if key == http.HeaderOrderKey || key == http.PHeaderOrderKey {
        continue
    }
    if _, exists := getHeaderCaseInsensitive(req.Headers, key); !exists {
        req.Headers[key] = values
    }
}
```

**Benefit:** `resp.Request.Headers` now shows all headers actually sent - useful for debugging.

---

## Testing

After fixes, test:
1. `req.GetHeader("Host")` when set as `"host"`
2. `req.GetHeader("host")` when set as `"Host"`
3. Setting `"accept": ["application/json"]` and verify mode detection works
4. Setting `"host": ["example.com"]` and verify no duplicate Host headers
