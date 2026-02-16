# 🛰️ Advanced Network Tools - Professional Diagnostic Suite

A comprehensive, production-ready network diagnostic API powered by Cloudflare Workers featuring **18 professional-grade tools** for network analysis, security auditing, and troubleshooting.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/YOUR_REPO)

## 🌟 Features

### Core Network Tools (5)
1. **DNS Lookup** - Query any DNS record type via Cloudflare's DoH
2. **HTTP/HTTPS Checker** - Test endpoint health and performance
3. **IP Geolocation** - Get visitor location and network info
4. **Headers Inspector** - View all request headers
5. **Ping/Latency Test** - Measure response times with statistics

### Email & Security Tools (4)
6. **SSL/TLS Certificate Inspector** - Validate HTTPS security
7. **SPF Record Checker** - Email authentication validation
8. **DMARC Checker** - Email policy and security
9. **Security Headers Analyzer** - Grade website security posture

### Advanced Network Tools (4)
10. **WHOIS Lookup** - Domain registration info via RDAP
11. **HTTP Version Checker** - Detect HTTP/2 & HTTP/3 support
12. **Reverse DNS** - PTR record lookups
13. **Port Connectivity** - TCP port testing with Cloudflare Sockets

### Utility Tools (5)
14. **Subnet Calculator** - CIDR network calculations
15. **Base64 Encoder/Decoder** - String encoding utilities
16. **Hash Generator** - Cryptographic hashes (SHA-1/256/384/512)
17. **URL Parser** - Parse and analyze URLs
18. **User Agent Parser** - Detect browser, OS, device type

## 🚀 Quick Start

### Prerequisites
- Node.js 18 or later
- A Cloudflare account (free tier works!)
- Wrangler CLI: `npm install -g wrangler`

### Installation

```bash
# Install dependencies
npm install

# Generate TypeScript types
npm run types

# Login to Cloudflare
wrangler login

# Run locally
npm run dev

# Deploy to production
npm run deploy
```

## 📖 Complete API Documentation

### Base URL
```
https://YOUR-WORKER.workers.dev
```

---

### 1. DNS Lookup 🔍

Query DNS records using Cloudflare's DNS over HTTPS (DoH).

**Endpoint:** `GET /dns`

**Parameters:**
- `domain` (required) - Domain name to query
- `type` (optional, default: A) - Record type: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/dns?domain=cloudflare.com&type=A"
```

**Response:**
```json
{
  "tool": "dns",
  "timestamp": "2026-02-16T10:00:00.000Z",
  "executionTime": 42,
  "result": {
    "domain": "cloudflare.com",
    "type": "A",
    "status": "success",
    "answers": [
      {
        "name": "cloudflare.com",
        "type": 1,
        "TTL": 300,
        "data": "104.16.132.229"
      }
    ],
    "authority": []
  }
}
```

---

### 2. HTTP/HTTPS Checker 🌐

Test endpoint health, status codes, and response time.

**Endpoint:** `GET /http-check`

**Parameters:**
- `url` (required) - Full URL to check

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/http-check?url=https://cloudflare.com"
```

**Response:**
```json
{
  "tool": "http-check",
  "executionTime": 150,
  "result": {
    "url": "https://cloudflare.com",
    "status": 200,
    "statusText": "OK",
    "ok": true,
    "responseTime": 148,
    "headers": {
      "content-type": "text/html",
      "server": "cloudflare"
    },
    "redirected": false
  }
}
```

---

### 3. IP Geolocation 📍

Get your IP address and geographic information.

**Endpoint:** `GET /ip-info`

**Parameters:** None

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/ip-info"
```

**Response:**
```json
{
  "tool": "ip-info",
  "executionTime": 2,
  "result": {
    "ip": "203.0.113.42",
    "country": "US",
    "city": "San Francisco",
    "continent": "NA",
    "latitude": "37.7749",
    "longitude": "-122.4194",
    "timezone": "America/Los_Angeles",
    "asn": "13335",
    "colo": "SFO"
  }
}
```

---

### 4. Headers Inspector 📋

Inspect all request headers including Cloudflare metadata.

**Endpoint:** `GET /headers`

**Parameters:** None

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/headers"
```

---

### 5. Ping / Latency Test ⚡

Measure response time with ping-like statistics.

**Endpoint:** `GET /ping`

**Parameters:**
- `url` (required) - Full URL to ping
- `count` (optional, default: 4, max: 10) - Number of pings

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/ping?url=https://cloudflare.com&count=5"
```

**Response:**
```json
{
  "tool": "ping",
  "executionTime": 2500,
  "result": {
    "url": "https://cloudflare.com",
    "count": 5,
    "results": [
      { "seq": 1, "time": 120, "status": 200, "ok": true },
      { "seq": 2, "time": 115, "status": 200, "ok": true }
    ],
    "statistics": {
      "min": 115,
      "max": 122,
      "avg": 118,
      "loss": "0%"
    }
  }
}
```

---

### 6. SSL/TLS Certificate Inspector 🔒

Check SSL/TLS certificate validity and security.

**Endpoint:** `GET /ssl` or `GET /certificate`

**Parameters:**
- `domain` (required) - Domain or full URL to check

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/ssl?domain=cloudflare.com"
```

---

### 7. WHOIS Lookup 📜

Domain registration information via RDAP protocol.

**Endpoint:** `GET /whois`

**Parameters:**
- `domain` (required) - Domain name

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/whois?domain=cloudflare.com"
```

**Response:**
```json
{
  "tool": "whois",
  "executionTime": 650,
  "result": {
    "domain": "cloudflare.com",
    "registrar": "MarkMonitor Inc.",
    "status": ["clientTransferProhibited"],
    "created": "2009-02-17T00:00:00Z",
    "updated": "2024-01-16T00:00:00Z",
    "expires": "2025-02-17T00:00:00Z",
    "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"]
  }
}
```

---

### 8. SPF Record Checker 📧

Validate Sender Policy Framework records for email authentication.

**Endpoint:** `GET /spf`

**Parameters:**
- `domain` (required) - Domain name

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/spf?domain=cloudflare.com"
```

**Response:**
```json
{
  "tool": "spf",
  "executionTime": 120,
  "result": {
    "domain": "cloudflare.com",
    "exists": true,
    "record": "v=spf1 include:_spf.cloudflare.com ~all",
    "mechanisms": ["v=spf1", "include:_spf.cloudflare.com", "~all"],
    "dnsLookups": 1,
    "valid": true,
    "warnings": []
  }
}
```

---

### 9. DMARC Checker 🛡️

Check DMARC policy and email security configuration.

**Endpoint:** `GET /dmarc`

**Parameters:**
- `domain` (required) - Domain name

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/dmarc?domain=cloudflare.com"
```

**Response:**
```json
{
  "tool": "dmarc",
  "executionTime": 130,
  "result": {
    "domain": "cloudflare.com",
    "exists": true,
    "record": "v=DMARC1; p=reject; rua=mailto:dmarc@cloudflare.com",
    "policy": "reject",
    "subdomainPolicy": "reject",
    "percentage": "100",
    "reportingAddresses": {
      "aggregate": "mailto:dmarc@cloudflare.com",
      "forensic": "none"
    }
  }
}
```

---

### 10. Security Headers Analyzer 🔐

Analyze security headers and grade website security posture.

**Endpoint:** `GET /security-headers`

**Parameters:**
- `url` (required) - Full URL to analyze

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/security-headers?url=https://cloudflare.com"
```

**Response:**
```json
{
  "tool": "security-headers",
  "executionTime": 200,
  "result": {
    "url": "https://cloudflare.com",
    "headers": {
      "Strict-Transport-Security": "max-age=31536000",
      "Content-Security-Policy": "default-src 'self'",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer"
    },
    "score": "8/9",
    "grade": "A"
  }
}
```

---

### 11. HTTP Version Checker 🚀

Detect HTTP/2 and HTTP/3 support.

**Endpoint:** `GET /http-version`

**Parameters:**
- `url` (required) - Full URL to check

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/http-version?url=https://cloudflare.com"
```

---

### 12. Reverse DNS Lookup 🔄

Perform reverse DNS lookup (PTR record).

**Endpoint:** `GET /reverse-dns`

**Parameters:**
- `ip` (required) - IPv4 address

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/reverse-dns?ip=1.1.1.1"
```

**Response:**
```json
{
  "tool": "reverse-dns",
  "executionTime": 80,
  "result": {
    "ip": "1.1.1.1",
    "hostnames": ["one.one.one.one"],
    "found": true
  }
}
```

---

### 13. Port Connectivity Checker 🔌

Test TCP port connectivity using Cloudflare Sockets.

**Endpoint:** `GET /port-check`

**Parameters:**
- `host` (required) - Hostname or IP address
- `port` (required) - Port number (1-65535, except 25)

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/port-check?host=cloudflare.com&port=443"
```

**Response:**
```json
{
  "tool": "port-check",
  "executionTime": 150,
  "result": {
    "host": "cloudflare.com",
    "port": 443,
    "open": true,
    "responseTime": 148
  }
}
```

**Note:** Port 25 (SMTP) is blocked by Cloudflare Workers.

---

### 14. Subnet Calculator 🔢

Calculate network information from CIDR notation.

**Endpoint:** `GET /subnet`

**Parameters:**
- `cidr` (required) - CIDR notation (e.g., 192.168.1.0/24)

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/subnet?cidr=192.168.1.0/24"
```

**Response:**
```json
{
  "tool": "subnet",
  "executionTime": 1,
  "result": {
    "cidr": "192.168.1.0/24",
    "network": "192.168.1.0",
    "broadcast": "192.168.1.255",
    "netmask": "255.255.255.0",
    "wildcardMask": "0.0.0.255",
    "firstHost": "192.168.1.1",
    "lastHost": "192.168.1.254",
    "totalHosts": 256,
    "usableHosts": 254,
    "prefix": 24
  }
}
```

---

### 15. Base64 Encoder/Decoder 🔤

Encode or decode Base64 strings.

**Endpoint:** `GET /base64`

**Parameters:**
- `input` (required) - String to encode/decode
- `op` (optional, default: encode) - Operation: `encode` or `decode`

**Example:**
```bash
# Encode
curl "https://YOUR-WORKER.workers.dev/base64?input=Hello%20World&op=encode"

# Decode
curl "https://YOUR-WORKER.workers.dev/base64?input=SGVsbG8gV29ybGQ=&op=decode"
```

---

### 16. Hash Generator 🔐

Generate cryptographic hashes.

**Endpoint:** `GET /hash`

**Parameters:**
- `input` (required) - String to hash
- `algo` (optional, default: SHA-256) - Algorithm: SHA-1, SHA-256, SHA-384, SHA-512

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/hash?input=Hello%20World&algo=SHA-256"
```

**Response:**
```json
{
  "tool": "hash",
  "executionTime": 2,
  "result": {
    "input": "Hello World",
    "algorithm": "SHA-256",
    "hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
  }
}
```

---

### 17. URL Parser 🔗

Parse URL into components.

**Endpoint:** `GET /url-parse`

**Parameters:**
- `url` (required) - URL to parse

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/url-parse?url=https://example.com:8080/path?key=value%23hash"
```

**Response:**
```json
{
  "tool": "url-parse",
  "executionTime": 1,
  "result": {
    "original": "https://example.com:8080/path?key=value#hash",
    "protocol": "https:",
    "hostname": "example.com",
    "port": "8080",
    "pathname": "/path",
    "search": "?key=value",
    "hash": "#hash",
    "origin": "https://example.com:8080",
    "params": { "key": "value" }
  }
}
```

---

### 18. User Agent Parser 🖥️

Detect browser, OS, and device type from User-Agent.

**Endpoint:** `GET /user-agent`

**Parameters:** None (uses your request's User-Agent header)

**Example:**
```bash
curl "https://YOUR-WORKER.workers.dev/user-agent"
```

**Response:**
```json
{
  "tool": "user-agent",
  "executionTime": 1,
  "result": {
    "userAgent": "Mozilla/5.0 ...",
    "browser": "Chrome",
    "os": "Windows",
    "deviceType": "desktop",
    "isBot": false
  }
}
```

---

## 🏗️ Architecture & Best Practices

This Worker follows **all** Cloudflare Workers best practices:

✅ **Streaming** - HTTP responses stream without buffering (no memory overflow)  
✅ **Background Tasks** - Uses `ctx.waitUntil()` for caching and analytics  
✅ **No Global State** - All state passed through function arguments  
✅ **Caching** - DNS (5min) and WHOIS (1hr) results cached in KV  
✅ **TypeScript** - Full type safety with generated Env types  
✅ **Modern Config** - `wrangler.jsonc` with `nodejs_compat`  
✅ **Observability** - Logs (100%) and traces (10%) enabled  
✅ **Structured Logging** - JSON logs for searchability  
✅ **Error Handling** - Try/catch with detailed error responses  
✅ **CORS Support** - Ready for cross-origin API access  
✅ **TCP Sockets** - Uses Cloudflare's `connect()` API for port checking  
✅ **Web Crypto** - Secure hash generation with Web Crypto API  

## 🔧 Configuration

### KV Namespace (Optional but Recommended)

To enable caching, create a KV namespace:

```bash
wrangler kv:namespace create CACHE
```

Update `wrangler.jsonc` with the returned namespace ID.

### Environment Variables

No environment variables or secrets required! All tools work out of the box.

### Observability

View logs and traces in the Cloudflare dashboard:
- Workers → Your Worker → Observability
- Or use: `npm run tail`

## 📊 Performance

- **Global Edge Deployment** - 300+ cities worldwide
- **Sub-50ms Response Times** - For most tools
- **Intelligent Caching** - DNS (5min), WHOIS (1hr) TTL
- **Rate Limiting** - CPU time limit: 50ms per request

## 🔐 Security

- **CORS Enabled** - `Access-Control-Allow-Origin: *` for public API
- **Input Validation** - All parameters validated before processing
- **Timeout Protection** - 10s for HTTP requests, 5s for pings
- **No Secrets Logged** - Structured logging excludes sensitive data
- **Port 25 Blocked** - SMTP port blocked per Cloudflare policy

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional DNS record types
- More security header checks
- IPv6 support for more tools
- WebSocket connectivity testing
- MTU path discovery

## 📝 License

MIT License - Use freely for any purpose!

## 🔗 Resources

- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Workers Best Practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/)
- [TCP Sockets API](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

## 💡 Use Cases

- **DevOps & SRE** - Quick network diagnostics from anywhere
- **Security Audits** - Check SPF, DMARC, security headers
- **API Development** - Test endpoints, check headers, validate URLs
- **Network Troubleshooting** - DNS, reverse DNS, port connectivity
- **Educational** - Learn about networking protocols and security

---

**Built with ❤️ using Cloudflare Workers**

Deploy globally in seconds. Run at the edge. Scale automatically.
