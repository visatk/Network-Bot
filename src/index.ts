import { connect } from "cloudflare:sockets";

interface Env {
  CACHE?: KVNamespace;
}

interface ToolResponse {
  tool: string;
  timestamp: string;
  executionTime: number;
  result: unknown;
  cached?: boolean;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const startTime = Date.now();

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json; charset=utf-8",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      const path = url.pathname;

      // Landing page
      if (path === "/" || path === "") {
        return handleHomePage(corsHeaders);
      }

      // Route to appropriate tool
      const result = await routeToTool(path, url, request, env, ctx);
      const executionTime = Date.now() - startTime;

      if (result === null) {
        return Response.json(
          {
            error: "Tool not found",
            available: getAllToolPaths(),
          },
          { status: 404, headers: corsHeaders }
        );
      }

      return Response.json(
        {
          ...result,
          executionTime,
        } as ToolResponse,
        { headers: corsHeaders }
      );
    } catch (error) {
      console.error(
        JSON.stringify({
          message: "request failed",
          error: error instanceof Error ? error.message : String(error),
          path: url.pathname,
        })
      );

      return Response.json(
        {
          error: "Internal server error",
          message: error instanceof Error ? error.message : "Unknown error",
        },
        { status: 500, headers: corsHeaders }
      );
    }
  },
} satisfies ExportedHandler<Env>;

async function routeToTool(
  path: string,
  url: URL,
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Partial<ToolResponse> | null> {
  switch (path) {
    case "/dns":
      return await handleDNS(url, env, ctx);
    case "/http-check":
      return await handleHTTPCheck(url, ctx);
    case "/ip-info":
      return handleIPInfo(request);
    case "/headers":
      return handleHeaders(request);
    case "/ping":
      return await handlePing(url, ctx);
    case "/ssl":
    case "/certificate":
      return await handleSSL(url, ctx);
    case "/whois":
      return await handleWHOIS(url, env, ctx);
    case "/spf":
      return await handleSPF(url, env, ctx);
    case "/dmarc":
      return await handleDMARC(url, env, ctx);
    case "/security-headers":
      return await handleSecurityHeaders(url, ctx);
    case "/http-version":
      return await handleHTTPVersion(url, ctx);
    case "/reverse-dns":
      return await handleReverseDNS(url, env, ctx);
    case "/subnet":
      return handleSubnet(url);
    case "/base64":
      return handleBase64(url);
    case "/hash":
      return await handleHash(url);
    case "/url-parse":
      return handleURLParse(url);
    case "/user-agent":
      return handleUserAgent(request);
    case "/port-check":
      return await handlePortCheck(url, ctx);
    default:
      return null;
  }
}

// ============= DNS LOOKUP =============
async function handleDNS(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain");
  const type = url.searchParams.get("type")?.toUpperCase() || "A";

  if (!domain) {
    throw new Error("Missing 'domain' parameter");
  }

  const cacheKey = `dns:${domain}:${type}`;
  
  if (env.CACHE) {
    const cached = await env.CACHE.get(cacheKey, "json");
    if (cached) {
      return {
        tool: "dns",
        timestamp: new Date().toISOString(),
        result: { ...cached, cached: true },
      };
    }
  }

  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
  
  const response = await fetch(dohUrl, {
    headers: { Accept: "application/dns-json" },
  });

  const dnsData: any = await response.json();
  
  const result = {
    domain,
    type,
    status: dnsData.Status === 0 ? "success" : "error",
    answers: dnsData.Answer || [],
    authority: dnsData.Authority || [],
  };

  if (env.CACHE) {
    ctx.waitUntil(
      env.CACHE.put(cacheKey, JSON.stringify(result), {
        expirationTtl: 300,
      })
    );
  }

  return {
    tool: "dns",
    timestamp: new Date().toISOString(),
    result,
  };
}

// ============= HTTP CHECK =============
async function handleHTTPCheck(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  
  if (!targetUrl) {
    throw new Error("Missing 'url' parameter");
  }

  const startTime = performance.now();
  
  try {
    new URL(targetUrl); // Validate URL
    
    const response = await fetch(targetUrl, {
      method: "GET",
      signal: AbortSignal.timeout(10000),
    });

    const endTime = performance.now();
    const responseTime = Math.round(endTime - startTime);

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return {
      tool: "http-check",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        status: response.status,
        statusText: response.statusText,
        ok: response.ok,
        responseTime,
        headers: {
          "content-type": headers["content-type"],
          "server": headers["server"],
          "content-length": headers["content-length"],
          "cache-control": headers["cache-control"],
          "content-encoding": headers["content-encoding"],
        },
        redirected: response.redirected,
      },
    };
  } catch (error) {
    const endTime = performance.now();
    return {
      tool: "http-check",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        error: error instanceof Error ? error.message : "Unknown error",
        responseTime: Math.round(endTime - startTime),
        ok: false,
      },
    };
  }
}

// ============= IP INFO =============
function handleIPInfo(request: Request): Partial<ToolResponse> {
  return {
    tool: "ip-info",
    timestamp: new Date().toISOString(),
    result: {
      ip: request.headers.get("CF-Connecting-IP") || "unknown",
      country: request.headers.get("CF-IPCountry") || "unknown",
      city: request.headers.get("CF-IPCity") || "unknown",
      continent: request.headers.get("CF-IPContinent") || "unknown",
      latitude: request.headers.get("CF-IPLatitude") || "unknown",
      longitude: request.headers.get("CF-IPLongitude") || "unknown",
      timezone: request.headers.get("CF-Timezone") || "unknown",
      asn: request.headers.get("CF-ASN") || "unknown",
      colo: request.headers.get("CF-Ray")?.split("-")[1] || "unknown",
    },
  };
}

// ============= HEADERS INSPECTOR =============
function handleHeaders(request: Request): Partial<ToolResponse> {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    headers[key] = value;
  });

  return {
    tool: "headers",
    timestamp: new Date().toISOString(),
    result: {
      headers,
      count: Object.keys(headers).length,
      cloudflare: {
        ray: request.headers.get("CF-Ray"),
        visitor: request.headers.get("CF-Visitor"),
        ipCountry: request.headers.get("CF-IPCountry"),
        connectingIp: request.headers.get("CF-Connecting-IP"),
        colo: request.headers.get("CF-Ray")?.split("-")[1],
      },
    },
  };
}

// ============= PING =============
async function handlePing(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  const count = Math.min(parseInt(url.searchParams.get("count") || "4"), 10);
  
  if (!targetUrl) {
    throw new Error("Missing 'url' parameter");
  }

  const results = [];

  for (let i = 0; i < count; i++) {
    const startTime = performance.now();
    
    try {
      const response = await fetch(targetUrl, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      });

      const time = Math.round(performance.now() - startTime);

      results.push({
        seq: i + 1,
        time,
        status: response.status,
        ok: response.ok,
      });
    } catch (error) {
      results.push({
        seq: i + 1,
        time: Math.round(performance.now() - startTime),
        error: error instanceof Error ? error.message : "Unknown error",
        ok: false,
      });
    }

    if (i < count - 1) {
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  const successfulPings = results.filter(r => r.ok);
  const times = successfulPings.map(r => r.time);
  
  const stats = times.length > 0 ? {
    min: Math.min(...times),
    max: Math.max(...times),
    avg: Math.round(times.reduce((a, b) => a + b, 0) / times.length),
    loss: `${Math.round((1 - successfulPings.length / count) * 100)}%`,
  } : null;

  return {
    tool: "ping",
    timestamp: new Date().toISOString(),
    result: {
      url: targetUrl,
      count,
      results,
      statistics: stats,
    },
  };
}

// ============= SSL/TLS CERTIFICATE =============
async function handleSSL(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain") || url.searchParams.get("url");
  
  if (!domain) {
    throw new Error("Missing 'domain' parameter");
  }

  // Extract hostname from URL if full URL provided
  const hostname = domain.startsWith("http") ? new URL(domain).hostname : domain;
  const targetUrl = `https://${hostname}`;

  try {
    const response = await fetch(targetUrl, {
      method: "HEAD",
      signal: AbortSignal.timeout(10000),
    });

    // Get certificate info from response headers
    const certInfo = {
      hostname,
      valid: response.ok,
      protocol: response.headers.get("cf-ray") ? "https" : "unknown",
      server: response.headers.get("server"),
      strictTransportSecurity: response.headers.get("strict-transport-security"),
      // Note: Full cert details require TCP socket inspection which is limited
      note: "Full certificate chain inspection requires server-side TLS termination access",
    };

    return {
      tool: "ssl",
      timestamp: new Date().toISOString(),
      result: certInfo,
    };
  } catch (error) {
    return {
      tool: "ssl",
      timestamp: new Date().toISOString(),
      result: {
        hostname,
        error: error instanceof Error ? error.message : "Unknown error",
        valid: false,
      },
    };
  }
}

// ============= WHOIS LOOKUP =============
async function handleWHOIS(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain");
  
  if (!domain) {
    throw new Error("Missing 'domain' parameter");
  }

  const cacheKey = `whois:${domain}`;
  
  if (env.CACHE) {
    const cached = await env.CACHE.get(cacheKey, "json");
    if (cached) {
      return {
        tool: "whois",
        timestamp: new Date().toISOString(),
        result: { ...cached, cached: true },
      };
    }
  }

  // Use RDAP (Registration Data Access Protocol) - modern WHOIS alternative
  const tld = domain.split(".").pop();
  const rdapUrl = `https://rdap.org/domain/${domain}`;

  try {
    const response = await fetch(rdapUrl, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      throw new Error(`RDAP query failed: ${response.status}`);
    }

    const rdapData: any = await response.json();
    
    const result = {
      domain,
      registrar: rdapData.entities?.find((e: any) => e.roles?.includes("registrar"))?.vcardArray?.[1]?.[1]?.[3] || "Unknown",
      status: rdapData.status || [],
      created: rdapData.events?.find((e: any) => e.eventAction === "registration")?.eventDate || "Unknown",
      updated: rdapData.events?.find((e: any) => e.eventAction === "last changed")?.eventDate || "Unknown",
      expires: rdapData.events?.find((e: any) => e.eventAction === "expiration")?.eventDate || "Unknown",
      nameservers: rdapData.nameservers?.map((ns: any) => ns.ldhName) || [],
    };

    if (env.CACHE) {
      ctx.waitUntil(
        env.CACHE.put(cacheKey, JSON.stringify(result), {
          expirationTtl: 3600, // 1 hour
        })
      );
    }

    return {
      tool: "whois",
      timestamp: new Date().toISOString(),
      result,
    };
  } catch (error) {
    return {
      tool: "whois",
      timestamp: new Date().toISOString(),
      result: {
        domain,
        error: error instanceof Error ? error.message : "RDAP lookup failed",
        note: "Some TLDs may not support RDAP. Try using a dedicated WHOIS service.",
      },
    };
  }
}

// ============= SPF CHECKER =============
async function handleSPF(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain");
  
  if (!domain) {
    throw new Error("Missing 'domain' parameter");
  }

  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=TXT`;
  
  const response = await fetch(dohUrl, {
    headers: { Accept: "application/dns-json" },
  });

  const dnsData: any = await response.json();
  const txtRecords = dnsData.Answer?.filter((a: any) => a.type === 16) || [];
  
  const spfRecord = txtRecords.find((record: any) => 
    record.data.includes("v=spf1")
  );

  if (!spfRecord) {
    return {
      tool: "spf",
      timestamp: new Date().toISOString(),
      result: {
        domain,
        exists: false,
        message: "No SPF record found",
      },
    };
  }

  const spfData = spfRecord.data.replace(/"/g, "");
  const mechanisms = spfData.split(" ").filter((m: string) => m.length > 0);
  
  // Count DNS lookups (include, a, mx, ptr, exists)
  const dnsLookups = mechanisms.filter((m: string) => 
    m.startsWith("include:") || m.startsWith("a:") || m.startsWith("mx:") || 
    m.startsWith("ptr:") || m.startsWith("exists:")
  ).length;

  return {
    tool: "spf",
    timestamp: new Date().toISOString(),
    result: {
      domain,
      exists: true,
      record: spfData,
      mechanisms,
      dnsLookups,
      valid: dnsLookups <= 10, // SPF spec limits to 10 DNS lookups
      warnings: dnsLookups > 10 ? ["Too many DNS lookups (>10), may cause PERMERROR"] : [],
    },
  };
}

// ============= DMARC CHECKER =============
async function handleDMARC(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain");
  
  if (!domain) {
    throw new Error("Missing 'domain' parameter");
  }

  const dmarcDomain = `_dmarc.${domain}`;
  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(dmarcDomain)}&type=TXT`;
  
  const response = await fetch(dohUrl, {
    headers: { Accept: "application/dns-json" },
  });

  const dnsData: any = await response.json();
  const txtRecords = dnsData.Answer?.filter((a: any) => a.type === 16) || [];
  
  const dmarcRecord = txtRecords.find((record: any) => 
    record.data.includes("v=DMARC1")
  );

  if (!dmarcRecord) {
    return {
      tool: "dmarc",
      timestamp: new Date().toISOString(),
      result: {
        domain,
        exists: false,
        message: "No DMARC record found",
      },
    };
  }

  const dmarcData = dmarcRecord.data.replace(/"/g, "");
  const tags: Record<string, string> = {};
  
  dmarcData.split(";").forEach((tag: string) => {
    const [key, value] = tag.trim().split("=");
    if (key && value) {
      tags[key.trim()] = value.trim();
    }
  });

  return {
    tool: "dmarc",
    timestamp: new Date().toISOString(),
    result: {
      domain,
      exists: true,
      record: dmarcData,
      policy: tags.p || "none",
      subdomainPolicy: tags.sp || tags.p || "none",
      percentage: tags.pct || "100",
      reportingAddresses: {
        aggregate: tags.rua || "none",
        forensic: tags.ruf || "none",
      },
      tags,
    },
  };
}

// ============= SECURITY HEADERS =============
async function handleSecurityHeaders(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  
  if (!targetUrl) {
    throw new Error("Missing 'url' parameter");
  }

  try {
    const response = await fetch(targetUrl, {
      method: "HEAD",
      signal: AbortSignal.timeout(10000),
    });

    const securityHeaders = {
      "Strict-Transport-Security": response.headers.get("strict-transport-security") || "not set",
      "Content-Security-Policy": response.headers.get("content-security-policy") || "not set",
      "X-Frame-Options": response.headers.get("x-frame-options") || "not set",
      "X-Content-Type-Options": response.headers.get("x-content-type-options") || "not set",
      "Referrer-Policy": response.headers.get("referrer-policy") || "not set",
      "Permissions-Policy": response.headers.get("permissions-policy") || "not set",
      "Cross-Origin-Embedder-Policy": response.headers.get("cross-origin-embedder-policy") || "not set",
      "Cross-Origin-Opener-Policy": response.headers.get("cross-origin-opener-policy") || "not set",
      "Cross-Origin-Resource-Policy": response.headers.get("cross-origin-resource-policy") || "not set",
    };

    const score = Object.values(securityHeaders).filter(v => v !== "not set").length;
    const maxScore = Object.keys(securityHeaders).length;
    const grade = score >= 8 ? "A" : score >= 6 ? "B" : score >= 4 ? "C" : score >= 2 ? "D" : "F";

    return {
      tool: "security-headers",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        headers: securityHeaders,
        score: `${score}/${maxScore}`,
        grade,
      },
    };
  } catch (error) {
    return {
      tool: "security-headers",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        error: error instanceof Error ? error.message : "Unknown error",
      },
    };
  }
}

// ============= HTTP VERSION CHECKER =============
async function handleHTTPVersion(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  
  if (!targetUrl) {
    throw new Error("Missing 'url' parameter");
  }

  try {
    const response = await fetch(targetUrl, {
      method: "HEAD",
      signal: AbortSignal.timeout(10000),
    });

    // Check CF-specific headers for HTTP version info
    const cfRay = response.headers.get("cf-ray");
    const altSvc = response.headers.get("alt-svc");
    
    return {
      tool: "http-version",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        http2: response.headers.has("cf-ray"), // Cloudflare always uses HTTP/2 or better
        http3: altSvc?.includes("h3") || false,
        altSvc: altSvc || "not advertised",
        note: "Detected via Cloudflare headers and Alt-Svc header",
      },
    };
  } catch (error) {
    return {
      tool: "http-version",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        error: error instanceof Error ? error.message : "Unknown error",
      },
    };
  }
}

// ============= REVERSE DNS =============
async function handleReverseDNS(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const ip = url.searchParams.get("ip");
  
  if (!ip) {
    throw new Error("Missing 'ip' parameter");
  }

  // Validate IP address
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) {
    throw new Error("Invalid IPv4 address");
  }

  // Reverse the IP for PTR lookup
  const reversedIP = ip.split(".").reverse().join(".");
  const ptrDomain = `${reversedIP}.in-addr.arpa`;

  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(ptrDomain)}&type=PTR`;
  
  const response = await fetch(dohUrl, {
    headers: { Accept: "application/dns-json" },
  });

  const dnsData: any = await response.json();
  const ptrRecords = dnsData.Answer?.filter((a: any) => a.type === 12) || [];

  return {
    tool: "reverse-dns",
    timestamp: new Date().toISOString(),
    result: {
      ip,
      hostnames: ptrRecords.map((r: any) => r.data),
      found: ptrRecords.length > 0,
    },
  };
}

// ============= SUBNET CALCULATOR =============
function handleSubnet(url: URL): Partial<ToolResponse> {
  const cidr = url.searchParams.get("cidr");
  
  if (!cidr) {
    throw new Error("Missing 'cidr' parameter (e.g., 192.168.1.0/24)");
  }

  const [ip, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr);

  if (prefix < 0 || prefix > 32) {
    throw new Error("Invalid CIDR prefix (must be 0-32)");
  }

  const ipParts = ip.split(".").map(Number);
  const ipInt = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];

  const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  const firstHost = network + 1;
  const lastHost = broadcast - 1;
  const totalHosts = Math.pow(2, 32 - prefix);

  const intToIP = (int: number) => {
    return [
      (int >>> 24) & 0xFF,
      (int >>> 16) & 0xFF,
      (int >>> 8) & 0xFF,
      int & 0xFF,
    ].join(".");
  };

  return {
    tool: "subnet",
    timestamp: new Date().toISOString(),
    result: {
      cidr,
      network: intToIP(network),
      broadcast: intToIP(broadcast),
      netmask: intToIP(mask),
      wildcardMask: intToIP(~mask >>> 0),
      firstHost: intToIP(firstHost),
      lastHost: intToIP(lastHost),
      totalHosts,
      usableHosts: totalHosts - 2,
      prefix,
    },
  };
}

// ============= BASE64 ENCODER/DECODER =============
function handleBase64(url: URL): Partial<ToolResponse> {
  const operation = url.searchParams.get("op") || "encode";
  const input = url.searchParams.get("input");

  if (!input) {
    throw new Error("Missing 'input' parameter");
  }

  let result: string;

  if (operation === "encode") {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(input);
    result = btoa(String.fromCharCode(...bytes));
  } else if (operation === "decode") {
    try {
      const decoded = atob(input);
      const bytes = new Uint8Array([...decoded].map(c => c.charCodeAt(0)));
      const decoder = new TextDecoder();
      result = decoder.decode(bytes);
    } catch {
      throw new Error("Invalid base64 input");
    }
  } else {
    throw new Error("Invalid operation (use 'encode' or 'decode')");
  }

  return {
    tool: "base64",
    timestamp: new Date().toISOString(),
    result: {
      operation,
      input: input.substring(0, 100) + (input.length > 100 ? "..." : ""),
      output: result.substring(0, 100) + (result.length > 100 ? "..." : ""),
      fullOutput: result,
    },
  };
}

// ============= HASH GENERATOR =============
async function handleHash(url: URL): Promise<Partial<ToolResponse>> {
  const input = url.searchParams.get("input");
  const algorithm = url.searchParams.get("algo") || "SHA-256";

  if (!input) {
    throw new Error("Missing 'input' parameter");
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(input);

  const validAlgos = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
  if (!validAlgos.includes(algorithm)) {
    throw new Error(`Invalid algorithm (use: ${validAlgos.join(", ")})`);
  }

  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hash = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

  return {
    tool: "hash",
    timestamp: new Date().toISOString(),
    result: {
      input: input.substring(0, 100) + (input.length > 100 ? "..." : ""),
      algorithm,
      hash,
    },
  };
}

// ============= URL PARSER =============
function handleURLParse(url: URL): Partial<ToolResponse> {
  const targetUrl = url.searchParams.get("url");
  
  if (!targetUrl) {
    throw new Error("Missing 'url' parameter");
  }

  try {
    const parsed = new URL(targetUrl);
    
    return {
      tool: "url-parse",
      timestamp: new Date().toISOString(),
      result: {
        original: targetUrl,
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || "default",
        pathname: parsed.pathname,
        search: parsed.search,
        hash: parsed.hash,
        origin: parsed.origin,
        params: Object.fromEntries(parsed.searchParams),
      },
    };
  } catch {
    throw new Error("Invalid URL");
  }
}

// ============= USER AGENT PARSER =============
function handleUserAgent(request: Request): Partial<ToolResponse> {
  const ua = request.headers.get("user-agent") || "unknown";
  
  // Basic user agent parsing
  const isMobile = /mobile/i.test(ua);
  const isTablet = /tablet|ipad/i.test(ua);
  const isBot = /bot|crawler|spider|crawling/i.test(ua);

  let browser = "unknown";
  if (/chrome/i.test(ua) && !/edg/i.test(ua)) browser = "Chrome";
  else if (/safari/i.test(ua) && !/chrome/i.test(ua)) browser = "Safari";
  else if (/firefox/i.test(ua)) browser = "Firefox";
  else if (/edg/i.test(ua)) browser = "Edge";
  else if (/opr/i.test(ua)) browser = "Opera";

  let os = "unknown";
  if (/windows/i.test(ua)) os = "Windows";
  else if (/mac os/i.test(ua)) os = "macOS";
  else if (/linux/i.test(ua)) os = "Linux";
  else if (/android/i.test(ua)) os = "Android";
  else if (/ios|iphone|ipad/i.test(ua)) os = "iOS";

  return {
    tool: "user-agent",
    timestamp: new Date().toISOString(),
    result: {
      userAgent: ua,
      browser,
      os,
      deviceType: isBot ? "bot" : isTablet ? "tablet" : isMobile ? "mobile" : "desktop",
      isBot,
    },
  };
}

// ============= PORT CONNECTIVITY CHECKER =============
async function handlePortCheck(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const host = url.searchParams.get("host");
  const portStr = url.searchParams.get("port");

  if (!host || !portStr) {
    throw new Error("Missing 'host' or 'port' parameter");
  }

  const port = parseInt(portStr);
  if (port < 1 || port > 65535) {
    throw new Error("Invalid port (must be 1-65535)");
  }

  // Note: Port 25 (SMTP) is blocked by Cloudflare Workers
  if (port === 25) {
    return {
      tool: "port-check",
      timestamp: new Date().toISOString(),
      result: {
        host,
        port,
        open: false,
        error: "Port 25 (SMTP) is blocked by Cloudflare Workers",
      },
    };
  }

  const startTime = performance.now();

  try {
    const socket = connect({
      hostname: host,
      port,
    });

    // Try to read/write to confirm connection
    const writer = socket.writable.getWriter();
    await writer.write(new Uint8Array([0]));
    await writer.close();

    const responseTime = Math.round(performance.now() - startTime);

    return {
      tool: "port-check",
      timestamp: new Date().toISOString(),
      result: {
        host,
        port,
        open: true,
        responseTime,
      },
    };
  } catch (error) {
    return {
      tool: "port-check",
      timestamp: new Date().toISOString(),
      result: {
        host,
        port,
        open: false,
        error: error instanceof Error ? error.message : "Connection failed",
        responseTime: Math.round(performance.now() - startTime),
      },
    };
  }
}

// ============= HELPER FUNCTIONS =============
function getAllToolPaths(): string[] {
  return [
    "/dns",
    "/http-check",
    "/ip-info",
    "/headers",
    "/ping",
    "/ssl",
    "/whois",
    "/spf",
    "/dmarc",
    "/security-headers",
    "/http-version",
    "/reverse-dns",
    "/subnet",
    "/base64",
    "/hash",
    "/url-parse",
    "/user-agent",
    "/port-check",
  ];
}

function handleHomePage(corsHeaders: Record<string, string>): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Advanced Network Tools - Professional Diagnostic Suite</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 20px;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      padding: 40px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    h1 {
      color: #667eea;
      font-size: 2.5rem;
      margin-bottom: 10px;
      text-align: center;
    }
    .subtitle {
      text-align: center;
      color: #666;
      margin-bottom: 40px;
      font-size: 1.1rem;
    }
    .tools-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 20px;
      margin-top: 30px;
    }
    .tool-card {
      background: #f8f9fa;
      border: 2px solid #e9ecef;
      border-radius: 8px;
      padding: 20px;
      transition: all 0.3s;
    }
    .tool-card:hover {
      border-color: #667eea;
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(102,126,234,0.2);
    }
    .tool-title {
      font-size: 1.3rem;
      color: #667eea;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .tool-icon {
      font-size: 1.5rem;
    }
    .tool-path {
      background: #667eea;
      color: white;
      padding: 4px 8px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.9rem;
      display: inline-block;
      margin: 8px 0;
    }
    .tool-desc {
      color: #666;
      margin-top: 10px;
      font-size: 0.95rem;
    }
    .tool-params {
      margin-top: 10px;
      font-size: 0.85rem;
      color: #888;
    }
    .footer {
      margin-top: 50px;
      padding-top: 30px;
      border-top: 2px solid #e9ecef;
      text-align: center;
      color: #666;
    }
    .badge {
      display: inline-block;
      background: #28a745;
      color: white;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.85rem;
      margin-left: 10px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛰️ Advanced Network Tools</h1>
    <p class="subtitle">Professional-grade network diagnostics powered by Cloudflare Workers <span class="badge">18 Tools</span></p>

    <div class="tools-grid">
      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🔍</span> DNS Lookup</div>
        <div class="tool-path">GET /dns?domain=example.com&type=A</div>
        <div class="tool-desc">Query DNS records: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA with DoH</div>
        <div class="tool-params">Params: domain (required), type (default: A)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🌐</span> HTTP/HTTPS Checker</div>
        <div class="tool-path">GET /http-check?url=https://example.com</div>
        <div class="tool-desc">Test endpoint health, status codes, response time, and headers</div>
        <div class="tool-params">Params: url (required)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">📍</span> IP Geolocation</div>
        <div class="tool-path">GET /ip-info</div>
        <div class="tool-desc">Get your IP address, country, city, coordinates, timezone, ASN</div>
        <div class="tool-params">No parameters needed</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">📋</span> Headers Inspector</div>
        <div class="tool-path">GET /headers</div>
        <div class="tool-desc">Inspect all request headers including Cloudflare metadata</div>
        <div class="tool-params">No parameters needed</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">⚡</span> Ping / Latency</div>
        <div class="tool-path">GET /ping?url=https://example.com</div>
        <div class="tool-desc">Measure response time with statistics (min/max/avg/loss)</div>
        <div class="tool-params">Params: url (required), count (default: 4)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🔒</span> SSL/TLS Certificate</div>
        <div class="tool-path">GET /ssl?domain=example.com</div>
        <div class="tool-desc">Check SSL/TLS certificate validity and security headers</div>
        <div class="tool-params">Params: domain (required)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">📜</span> WHOIS Lookup</div>
        <div class="tool-path">GET /whois?domain=example.com</div>
        <div class="tool-desc">Domain registration info via RDAP protocol</div>
        <div class="tool-params">Params: domain (required)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">📧</span> SPF Checker</div>
        <div class="tool-path">GET /spf?domain=example.com</div>
        <div class="tool-desc">Validate SPF records for email authentication</div>
        <div class="tool-params">Params: domain (required)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🛡️</span> DMARC Checker</div>
        <div class="tool-path">GET /dmarc?domain=example.com</div>
        <div class="tool-desc">Check DMARC policy and email security configuration</div>
        <div class="tool-params">Params: domain (required)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🔐</span> Security Headers</div>
        <div class="tool-path">GET /security-headers?url=https://example.com</div>
        <div class="tool-desc">Analyze security headers (HSTS, CSP, X-Frame-Options, etc.)</div>
        <div class="tool-params">Params: url (required)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🚀</span> HTTP Version</div>
        <div class="tool-path">GET /http-version?url=https://example.com</div>
        <div class="tool-desc">Detect HTTP/2 and HTTP/3 support</div>
        <div class="tool-params">Params: url (required)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🔄</span> Reverse DNS</div>
        <div class="tool-path">GET /reverse-dns?ip=8.8.8.8</div>
        <div class="tool-desc">Perform reverse DNS lookup (PTR record)</div>
        <div class="tool-params">Params: ip (required)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🔢</span> Subnet Calculator</div>
        <div class="tool-path">GET /subnet?cidr=192.168.1.0/24</div>
        <div class="tool-desc">Calculate network, broadcast, usable hosts from CIDR</div>
        <div class="tool-params">Params: cidr (required)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🔤</span> Base64 Encode/Decode</div>
        <div class="tool-path">GET /base64?input=hello&op=encode</div>
        <div class="tool-desc">Encode or decode Base64 strings</div>
        <div class="tool-params">Params: input (required), op (encode/decode)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🔐</span> Hash Generator</div>
        <div class="tool-path">GET /hash?input=hello&algo=SHA-256</div>
        <div class="tool-desc">Generate cryptographic hashes (SHA-1/256/384/512)</div>
        <div class="tool-params">Params: input (required), algo (default: SHA-256)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🔗</span> URL Parser</div>
        <div class="tool-path">GET /url-parse?url=https://example.com/path</div>
        <div class="tool-desc">Parse URL into protocol, hostname, path, query params</div>
        <div class="tool-params">Params: url (required)</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🖥️</span> User Agent Parser</div>
        <div class="tool-path">GET /user-agent</div>
        <div class="tool-desc">Detect browser, OS, and device type from User-Agent</div>
        <div class="tool-params">No parameters needed</div>
      </div>

      <div class="tool-card">
        <div class="tool-title"><span class="tool-icon">🔌</span> Port Checker</div>
        <div class="tool-path">GET /port-check?host=example.com&port=443</div>
        <div class="tool-desc">Test TCP port connectivity using Cloudflare Sockets</div>
        <div class="tool-params">Params: host (required), port (required)</div>
      </div>
    </div>

    <div class="footer">
      <p><strong>⚡ Powered by Cloudflare Workers</strong></p>
      <p>Global edge deployment • Sub-50ms latency • Built with best practices</p>
      <p style="margin-top: 10px; font-size: 0.9rem;">
        DNS caching (5min) • WHOIS caching (1hr) • Structured logging • Full observability
      </p>
    </div>
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: {
      ...corsHeaders,
      "Content-Type": "text/html; charset=utf-8",
    },
  });
}
