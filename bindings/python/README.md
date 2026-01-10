# HTTPCloak Python

Browser fingerprint emulation HTTP client with HTTP/1.1, HTTP/2, and HTTP/3 support.

## Installation

```bash
pip install httpcloak
```

## Quick Start

### Synchronous Usage

```python
from httpcloak import Session

# Create a session with Chrome fingerprint
session = Session(preset="chrome-143")

# Make requests
response = session.get("https://www.cloudflare.com/cdn-cgi/trace")
print(response.status_code)
print(response.text)

# POST request with JSON
response = session.post_json("https://api.example.com/data", {"key": "value"})

# POST request with form data
response = session.post("https://api.example.com/form", body="field1=value1&field2=value2")

# Custom headers
response = session.get("https://example.com", headers={"X-Custom": "value"})

# With proxy
session = Session(preset="chrome-143", proxy="http://user:pass@host:port")

# Always close when done
session.close()
```

### Context Manager (Recommended)

```python
from httpcloak import Session

with Session(preset="chrome-143") as session:
    response = session.get("https://example.com")
    print(response.text)
# Session automatically closed
```

### Asynchronous Usage

```python
import asyncio
from httpcloak import Session

async def main():
    session = Session(preset="chrome-143")

    # Async GET
    response = await session.get_async("https://example.com")
    print(response.text)

    # Async POST
    response = await session.post_async("https://api.example.com/data", body={"key": "value"})

    # Multiple concurrent requests
    responses = await asyncio.gather(
        session.get_async("https://example.com/1"),
        session.get_async("https://example.com/2"),
        session.get_async("https://example.com/3"),
    )

    session.close()

asyncio.run(main())
```

### Fast Response Mode

For performance-critical applications, use `get_fast()` which returns a lightweight response:

```python
from httpcloak import Session

with Session(preset="chrome-143") as session:
    # Fast mode - minimal overhead
    response = session.get_fast("https://example.com")
    data = bytes(response.content)  # Raw bytes
    print(f"Status: {response.status_code}")
    print(f"Size: {len(data)} bytes")
```

### Streaming Downloads

For large downloads, use streaming to avoid loading entire response into memory:

```python
from httpcloak import Session

with Session(preset="chrome-143") as session:
    # Stream a large file
    stream = session.get_stream("https://example.com/large-file.zip")
    print(f"Status: {stream.status_code}")
    print(f"Content-Length: {stream.content_length}")

    # Read in chunks
    with open("downloaded-file.zip", "wb") as f:
        for chunk in stream.read_chunks(65536):  # 64KB chunks
            f.write(chunk)

    stream.close()

# Or use context manager
with Session(preset="chrome-143") as session:
    with session.get_stream("https://example.com/large-file.zip") as stream:
        total = 0
        for chunk in stream.read_chunks(65536):
            total += len(chunk)
        print(f"Downloaded {total} bytes")
```

## Proxy Support

HTTPCloak supports HTTP, SOCKS5, and HTTP/3 (MASQUE) proxies with full fingerprint preservation.

### HTTP Proxy

```python
from httpcloak import Session

# Basic HTTP proxy
session = Session(preset="chrome-143", proxy="http://host:port")

# With authentication
session = Session(preset="chrome-143", proxy="http://user:pass@host:port")

# HTTPS proxy
session = Session(preset="chrome-143", proxy="https://user:pass@host:port")
```

### SOCKS5 Proxy

```python
from httpcloak import Session

# SOCKS5 proxy (with DNS resolution on proxy)
session = Session(preset="chrome-143", proxy="socks5h://host:port")

# With authentication
session = Session(preset="chrome-143", proxy="socks5h://user:pass@host:port")

response = session.get("https://www.cloudflare.com/cdn-cgi/trace")
print(response.protocol)  # h3 (HTTP/3 through SOCKS5!)
```

### HTTP/3 MASQUE Proxy

MASQUE (RFC 9484) enables HTTP/3 connections through compatible proxies:

```python
from httpcloak import Session

# MASQUE proxy (auto-detected for known providers like Bright Data)
session = Session(preset="chrome-143", proxy="https://user:pass@brd.superproxy.io:10001")

response = session.get("https://www.cloudflare.com/cdn-cgi/trace")
print(response.protocol)  # h3
```

### Split Proxy Configuration

Use different proxies for TCP (HTTP/1.1, HTTP/2) and UDP (HTTP/3) traffic:

```python
from httpcloak import Session

session = Session(
    preset="chrome-143",
    tcp_proxy="http://tcp-proxy:port",      # For HTTP/1.1, HTTP/2
    udp_proxy="https://masque-proxy:port"   # For HTTP/3
)
```

## Advanced Features

### Encrypted Client Hello (ECH)

ECH encrypts the SNI (Server Name Indication) to prevent traffic analysis. Works with all Cloudflare domains:

```python
from httpcloak import Session

# Enable ECH for Cloudflare domains
session = Session(preset="chrome-143", ech_config_domain="cloudflare-ech.com")

response = session.get("https://www.cloudflare.com/cdn-cgi/trace")
print(response.text)
# Output includes: sni=encrypted, http=http/3
```

### Domain Fronting (Connect-To)

Connect to one server while requesting a different domain:

```python
from httpcloak import Session

# Connect to claude.ai's IP but request www.cloudflare.com
session = Session(
    preset="chrome-143",
    connect_to={"www.cloudflare.com": "claude.ai"}
)

response = session.get("https://www.cloudflare.com/cdn-cgi/trace")
```

### Combined: SOCKS5 + ECH

Get HTTP/3 with encrypted SNI through a SOCKS5 proxy:

```python
from httpcloak import Session

session = Session(
    preset="chrome-143",
    proxy="socks5h://user:pass@host:port",
    ech_config_domain="cloudflare-ech.com"
)

response = session.get("https://www.cloudflare.com/cdn-cgi/trace")
# Response shows: http=http/3, sni=encrypted
```

## Cookie Management

```python
from httpcloak import Session

session = Session()

# Set a cookie
session.set_cookie("session_id", "abc123")

# Get all cookies
cookies = session.get_cookies()
print(cookies)

# Access cookies as property
print(session.cookies)

# Clear a cookie
session.clear_cookie("session_id")

# Clear all cookies
session.clear_cookies()

session.close()
```

## Session Configuration

```python
from httpcloak import Session

session = Session(
    preset="chrome-143",           # Browser fingerprint preset
    proxy=None,                    # Proxy URL
    tcp_proxy=None,                # Separate TCP proxy
    udp_proxy=None,                # Separate UDP proxy (MASQUE)
    timeout=30,                    # Request timeout in seconds
    http_version="auto",           # "auto", "h1", "h2", "h3"
    verify=True,                   # SSL certificate verification
    allow_redirects=True,          # Follow redirects
    max_redirects=10,              # Maximum redirect count
    retry=3,                       # Retry count on failure
    prefer_ipv4=False,             # Prefer IPv4 over IPv6
    auth=("user", "pass"),         # Default basic auth
    connect_to=None,               # Domain fronting map
    ech_config_domain=None         # ECH config domain
)
```

## Available Presets

```python
from httpcloak import available_presets

print(available_presets())
# ['chrome-143', 'chrome-143-windows', 'chrome-143-linux', 'chrome-143-macos',
#  'chrome-131', 'firefox-133', 'safari-18', ...]
```

## Response Object

### Standard Response

```python
response = session.get("https://example.com")

response.status_code   # int: HTTP status code
response.headers       # dict[str, list[str]]: Response headers (multi-value)
response.content       # bytes: Raw response body
response.text          # str: Response body as text
response.url           # str: Final URL after redirects
response.protocol      # str: Protocol used (h2, h3)
response.ok            # bool: True if status < 400
response.elapsed       # float: Request duration in seconds
response.cookies       # list: Cookies from response
response.history       # list: Redirect history
response.reason        # str: Status reason phrase

# Get specific header
content_type = response.get_header("Content-Type")
all_cookies = response.get_headers("Set-Cookie")

# Parse JSON
data = response.json()
```

### Fast Response

```python
response = session.get_fast("https://example.com")

response.status_code   # int: HTTP status code
response.headers       # dict: Response headers
response.content       # memoryview: Raw response body (zero-copy)
response.url           # str: Final URL after redirects
response.protocol      # str: Protocol used
```

### Streaming Response

```python
stream = session.get_stream("https://example.com")

stream.status_code      # int: HTTP status code
stream.headers          # dict[str, list[str]]: Response headers
stream.content_length   # int: Content length (-1 if unknown)
stream.url              # str: Final URL after redirects
stream.protocol         # str: Protocol used

# Read all bytes
data = stream.read_all()

# Read in chunks (memory efficient)
for chunk in stream.read_chunks(65536):
    process(chunk)

stream.close()
```

## HTTP Methods

```python
from httpcloak import Session

with Session(preset="chrome-143") as session:
    # GET
    response = session.get("https://example.com")

    # POST
    response = session.post("https://example.com", body="data")
    response = session.post_json("https://example.com", {"key": "value"})

    # PUT
    response = session.put("https://example.com", body="data")

    # PATCH
    response = session.patch("https://example.com", body="data")

    # DELETE
    response = session.delete("https://example.com")

    # HEAD
    response = session.head("https://example.com")

    # OPTIONS
    response = session.options("https://example.com")

    # Custom method
    response = session.request("CUSTOM", "https://example.com")
```

## Error Handling

```python
from httpcloak import Session, HTTPCloakError

try:
    session = Session()
    response = session.get("https://example.com")
except HTTPCloakError as e:
    print(f"Request failed: {e}")
finally:
    session.close()
```

## Convenience Functions

For one-off requests without managing a session:

```python
import httpcloak

# Simple GET
response = httpcloak.get("https://example.com")
print(response.text)

# With options
response = httpcloak.get(
    "https://example.com",
    headers={"X-Custom": "value"},
    timeout=60
)

# POST
response = httpcloak.post("https://api.example.com", body={"key": "value"})
```

## Platform Support

- Linux (x64, arm64)
- macOS (x64, arm64)
- Windows (x64, arm64)
- Python 3.8+

## License

MIT
