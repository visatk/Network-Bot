import { connect } from "cloudflare:sockets";

interface Env {
  CACHE?: KVNamespace;
}

interface ToolResponse {
  tool: string;
  timestamp: string;
  executionTime: number;
  result: unknown;
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

      if (path === "/" || path === "") {
        return handleHomePage(corsHeaders);
      }

      const result = await routeToTool(path, url, request, env, ctx);
      const executionTime = Date.now() - startTime;

      if (result === null) {
        return Response.json(
          { error: "Tool not found", available: getAllToolPaths() },
          { status: 404, headers: corsHeaders }
        );
      }

      return Response.json(
        { ...result, executionTime } as ToolResponse,
        { headers: corsHeaders }
      );
    } catch (error) {
      console.error(JSON.stringify({
        message: "request failed",
        error: error instanceof Error ? error.message : String(error),
        path: url.pathname,
      }));

      return Response.json(
        { error: "Internal server error", message: error instanceof Error ? error.message : "Unknown error" },
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
  const routes: Record<string, () => Promise<Partial<ToolResponse>>> = {
    "/dns": () => handleDNS(url, env, ctx),
    "/http-check": () => handleHTTPCheck(url, ctx),
    "/ip-info": () => Promise.resolve(handleIPInfo(request)),
    "/headers": () => Promise.resolve(handleHeaders(request)),
    "/ping": () => handlePing(url, ctx),
    "/ssl": () => handleSSL(url, ctx),
    "/certificate": () => handleSSL(url, ctx),
    "/spf": () => handleSPF(url, env, ctx),
    "/dmarc": () => handleDMARC(url, env, ctx),
    "/security-headers": () => handleSecurityHeaders(url, ctx),
    "/hsts-preload": () => handleHSTSPreload(url, ctx),
    "/caa": () => handleCAA(url, env, ctx),
    "/whois": () => handleWHOIS(url, env, ctx),
    "/http-version": () => handleHTTPVersion(url, ctx),
    "/reverse-dns": () => handleReverseDNS(url, env, ctx),
    "/port-check": () => handlePortCheck(url, ctx),
    "/asn": () => handleASN(url, env, ctx),
    "/bgp": () => handleBGP(url, env, ctx),
    "/dnssec": () => handleDNSSEC(url, env, ctx),
    "/robots": () => handleRobotsTxt(url, ctx),
    "/redirects": () => handleRedirects(url, ctx),
    "/meta-tags": () => handleMetaTags(url, ctx),
    "/http-methods": () => handleHTTPMethods(url, ctx),
    "/sitemap": () => handleSitemap(url, ctx),
    "/subnet": () => Promise.resolve(handleSubnet(url)),
    "/base64": () => Promise.resolve(handleBase64(url)),
    "/hash": () => handleHash(url),
    "/jwt": () => Promise.resolve(handleJWT(url)),
    "/json-validate": () => Promise.resolve(handleJSONValidate(url)),
    "/punycode": () => Promise.resolve(handlePunycode(url)),
    "/url-parse": () => Promise.resolve(handleURLParse(url)),
    "/user-agent": () => Promise.resolve(handleUserAgent(request)),
  };

  const handler = routes[path];
  return handler ? await handler() : null;
}

// ============= CORE NETWORK TOOLS =============

async function handleDNS(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain");
  const type = url.searchParams.get("type")?.toUpperCase() || "A";

  if (!domain) throw new Error("Missing 'domain' parameter");

  const cacheKey = `dns:${domain}:${type}`;
  
  if (env.CACHE) {
    const cached = await env.CACHE.get(cacheKey, "json");
    if (cached) {
      return { tool: "dns", timestamp: new Date().toISOString(), result: { ...cached, cached: true } };
    }
  }

  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
  const response = await fetch(dohUrl, { headers: { Accept: "application/dns-json" } });
  const dnsData: any = await response.json();
  
  const result = {
    domain,
    type,
    status: dnsData.Status === 0 ? "success" : "error",
    answers: dnsData.Answer || [],
    authority: dnsData.Authority || [],
  };

  if (env.CACHE) {
    ctx.waitUntil(env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 300 }));
  }

  return { tool: "dns", timestamp: new Date().toISOString(), result };
}

async function handleHTTPCheck(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  if (!targetUrl) throw new Error("Missing 'url' parameter");

  const startTime = performance.now();
  
  try {
    new URL(targetUrl);
    const response = await fetch(targetUrl, { method: "GET", signal: AbortSignal.timeout(10000) });
    const endTime = performance.now();

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => { headers[key] = value; });

    return {
      tool: "http-check",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        status: response.status,
        ok: response.ok,
        responseTime: Math.round(endTime - startTime),
        headers: {
          "content-type": headers["content-type"],
          "server": headers["server"],
          "cache-control": headers["cache-control"],
        },
        redirected: response.redirected,
      },
    };
  } catch (error) {
    return {
      tool: "http-check",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        error: error instanceof Error ? error.message : "Unknown error",
        responseTime: Math.round(performance.now() - startTime),
        ok: false,
      },
    };
  }
}

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

function handleHeaders(request: Request): Partial<ToolResponse> {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => { headers[key] = value; });

  return {
    tool: "headers",
    timestamp: new Date().toISOString(),
    result: {
      headers,
      count: Object.keys(headers).length,
      cloudflare: {
        ray: request.headers.get("CF-Ray"),
        ipCountry: request.headers.get("CF-IPCountry"),
        connectingIp: request.headers.get("CF-Connecting-IP"),
      },
    },
  };
}

async function handlePing(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  const count = Math.min(parseInt(url.searchParams.get("count") || "4"), 10);
  if (!targetUrl) throw new Error("Missing 'url' parameter");

  const results = [];
  for (let i = 0; i < count; i++) {
    const startTime = performance.now();
    try {
      const response = await fetch(targetUrl, { method: "HEAD", signal: AbortSignal.timeout(5000) });
      results.push({ seq: i + 1, time: Math.round(performance.now() - startTime), status: response.status, ok: response.ok });
    } catch (error) {
      results.push({ seq: i + 1, time: Math.round(performance.now() - startTime), error: error instanceof Error ? error.message : "Unknown error", ok: false });
    }
    if (i < count - 1) await new Promise(resolve => setTimeout(resolve, 500));
  }

  const successfulPings = results.filter(r => r.ok);
  const times = successfulPings.map(r => r.time);
  const stats = times.length > 0 ? {
    min: Math.min(...times),
    max: Math.max(...times),
    avg: Math.round(times.reduce((a, b) => a + b, 0) / times.length),
    loss: `${Math.round((1 - successfulPings.length / count) * 100)}%`,
  } : null;

  return { tool: "ping", timestamp: new Date().toISOString(), result: { url: targetUrl, count, results, statistics: stats } };
}

// ============= EMAIL & SECURITY TOOLS =============

async function handleSSL(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain") || url.searchParams.get("url");
  if (!domain) throw new Error("Missing 'domain' parameter");

  const hostname = domain.startsWith("http") ? new URL(domain).hostname : domain;
  const targetUrl = `https://${hostname}`;

  try {
    const response = await fetch(targetUrl, { method: "HEAD", signal: AbortSignal.timeout(10000) });
    return {
      tool: "ssl",
      timestamp: new Date().toISOString(),
      result: {
        hostname,
        valid: response.ok,
        protocol: "https",
        server: response.headers.get("server"),
        strictTransportSecurity: response.headers.get("strict-transport-security"),
      },
    };
  } catch (error) {
    return {
      tool: "ssl",
      timestamp: new Date().toISOString(),
      result: { hostname, error: error instanceof Error ? error.message : "Unknown error", valid: false },
    };
  }
}

async function handleSPF(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain");
  if (!domain) throw new Error("Missing 'domain' parameter");

  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=TXT`;
  const response = await fetch(dohUrl, { headers: { Accept: "application/dns-json" } });
  const dnsData: any = await response.json();
  const txtRecords = dnsData.Answer?.filter((a: any) => a.type === 16) || [];
  const spfRecord = txtRecords.find((record: any) => record.data.includes("v=spf1"));

  if (!spfRecord) {
    return { tool: "spf", timestamp: new Date().toISOString(), result: { domain, exists: false, message: "No SPF record found" } };
  }

  const spfData = spfRecord.data.replace(/"/g, "");
  const mechanisms = spfData.split(" ").filter((m: string) => m.length > 0);
  const dnsLookups = mechanisms.filter((m: string) => 
    m.startsWith("include:") || m.startsWith("a:") || m.startsWith("mx:") || m.startsWith("ptr:") || m.startsWith("exists:")
  ).length;

  return {
    tool: "spf",
    timestamp: new Date().toISOString(),
    result: { domain, exists: true, record: spfData, mechanisms, dnsLookups, valid: dnsLookups <= 10, warnings: dnsLookups > 10 ? ["Too many DNS lookups (>10)"] : [] },
  };
}

async function handleDMARC(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain");
  if (!domain) throw new Error("Missing 'domain' parameter");

  const dmarcDomain = `_dmarc.${domain}`;
  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(dmarcDomain)}&type=TXT`;
  const response = await fetch(dohUrl, { headers: { Accept: "application/dns-json" } });
  const dnsData: any = await response.json();
  const txtRecords = dnsData.Answer?.filter((a: any) => a.type === 16) || [];
  const dmarcRecord = txtRecords.find((record: any) => record.data.includes("v=DMARC1"));

  if (!dmarcRecord) {
    return { tool: "dmarc", timestamp: new Date().toISOString(), result: { domain, exists: false, message: "No DMARC record found" } };
  }

  const dmarcData = dmarcRecord.data.replace(/"/g, "");
  const tags: Record<string, string> = {};
  dmarcData.split(";").forEach((tag: string) => {
    const [key, value] = tag.trim().split("=");
    if (key && value) tags[key.trim()] = value.trim();
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
      reportingAddresses: { aggregate: tags.rua || "none", forensic: tags.ruf || "none" },
      tags,
    },
  };
}

async function handleSecurityHeaders(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  if (!targetUrl) throw new Error("Missing 'url' parameter");

  try {
    const response = await fetch(targetUrl, { method: "HEAD", signal: AbortSignal.timeout(10000) });
    const securityHeaders = {
      "Strict-Transport-Security": response.headers.get("strict-transport-security") || "not set",
      "Content-Security-Policy": response.headers.get("content-security-policy") || "not set",
      "X-Frame-Options": response.headers.get("x-frame-options") || "not set",
      "X-Content-Type-Options": response.headers.get("x-content-type-options") || "not set",
      "Referrer-Policy": response.headers.get("referrer-policy") || "not set",
      "Permissions-Policy": response.headers.get("permissions-policy") || "not set",
    };

    const score = Object.values(securityHeaders).filter(v => v !== "not set").length;
    const maxScore = Object.keys(securityHeaders).length;
    const grade = score >= 5 ? "A" : score >= 4 ? "B" : score >= 3 ? "C" : score >= 2 ? "D" : "F";

    return { tool: "security-headers", timestamp: new Date().toISOString(), result: { url: targetUrl, headers: securityHeaders, score: `${score}/${maxScore}`, grade } };
  } catch (error) {
    return { tool: "security-headers", timestamp: new Date().toISOString(), result: { url: targetUrl, error: error instanceof Error ? error.message : "Unknown error" } };
  }
}

async function handleHSTSPreload(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url") || url.searchParams.get("domain");
  if (!targetUrl) throw new Error("Missing 'url' or 'domain' parameter");

  const hostname = targetUrl.startsWith("http") ? new URL(targetUrl).hostname : targetUrl;

  try {
    const response = await fetch(`https://${hostname}`, { method: "HEAD", signal: AbortSignal.timeout(10000) });
    const hstsHeader = response.headers.get("strict-transport-security");

    if (!hstsHeader) {
      return {
        tool: "hsts-preload",
        timestamp: new Date().toISOString(),
        result: { domain: hostname, hstsEnabled: false, preloadReady: false, message: "No HSTS header found" },
      };
    }

    const maxAge = hstsHeader.match(/max-age=(\d+)/)?.[1];
    const includeSubDomains = hstsHeader.includes("includeSubDomains");
    const preload = hstsHeader.includes("preload");
    const maxAgeSeconds = maxAge ? parseInt(maxAge) : 0;
    const oneYear = 31536000;

    const preloadReady = maxAgeSeconds >= oneYear && includeSubDomains && preload;

    return {
      tool: "hsts-preload",
      timestamp: new Date().toISOString(),
      result: {
        domain: hostname,
        hstsEnabled: true,
        hstsHeader,
        maxAge: maxAgeSeconds,
        maxAgeHuman: `${Math.round(maxAgeSeconds / 86400)} days`,
        includeSubDomains,
        preload,
        preloadReady,
        requirements: {
          maxAgeOneYear: maxAgeSeconds >= oneYear,
          includeSubDomains,
          preloadDirective: preload,
        },
      },
    };
  } catch (error) {
    return {
      tool: "hsts-preload",
      timestamp: new Date().toISOString(),
      result: { domain: hostname, error: error instanceof Error ? error.message : "Unknown error" },
    };
  }
}

async function handleCAA(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain");
  if (!domain) throw new Error("Missing 'domain' parameter");

  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=CAA`;
  const response = await fetch(dohUrl, { headers: { Accept: "application/dns-json" } });
  const dnsData: any = await response.json();
  const caaRecords = dnsData.Answer?.filter((a: any) => a.type === 257) || [];

  if (caaRecords.length === 0) {
    return {
      tool: "caa",
      timestamp: new Date().toISOString(),
      result: { domain, exists: false, message: "No CAA records found (any CA can issue certificates)" },
    };
  }

  const parsedRecords = caaRecords.map((record: any) => {
    const parts = record.data.split(" ");
    return {
      flags: parts[0],
      tag: parts[1],
      value: parts.slice(2).join(" ").replace(/"/g, ""),
    };
  });

  return {
    tool: "caa",
    timestamp: new Date().toISOString(),
    result: { domain, exists: true, records: parsedRecords, count: parsedRecords.length },
  };
}

// ============= ADVANCED NETWORK TOOLS =============

async function handleWHOIS(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain");
  if (!domain) throw new Error("Missing 'domain' parameter");

  const cacheKey = `whois:${domain}`;
  if (env.CACHE) {
    const cached = await env.CACHE.get(cacheKey, "json");
    if (cached) {
      return { tool: "whois", timestamp: new Date().toISOString(), result: { ...cached, cached: true } };
    }
  }

  const rdapUrl = `https://rdap.org/domain/${domain}`;
  try {
    const response = await fetch(rdapUrl, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error(`RDAP query failed: ${response.status}`);

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
      ctx.waitUntil(env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 }));
    }

    return { tool: "whois", timestamp: new Date().toISOString(), result };
  } catch (error) {
    return {
      tool: "whois",
      timestamp: new Date().toISOString(),
      result: { domain, error: error instanceof Error ? error.message : "RDAP lookup failed" },
    };
  }
}

async function handleHTTPVersion(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  if (!targetUrl) throw new Error("Missing 'url' parameter");

  try {
    const response = await fetch(targetUrl, { method: "HEAD", signal: AbortSignal.timeout(10000) });
    const altSvc = response.headers.get("alt-svc");
    
    return {
      tool: "http-version",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        http2: response.headers.has("cf-ray"),
        http3: altSvc?.includes("h3") || false,
        altSvc: altSvc || "not advertised",
      },
    };
  } catch (error) {
    return { tool: "http-version", timestamp: new Date().toISOString(), result: { url: targetUrl, error: error instanceof Error ? error.message : "Unknown error" } };
  }
}

async function handleReverseDNS(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const ip = url.searchParams.get("ip");
  if (!ip) throw new Error("Missing 'ip' parameter");

  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) throw new Error("Invalid IPv4 address");

  const reversedIP = ip.split(".").reverse().join(".");
  const ptrDomain = `${reversedIP}.in-addr.arpa`;
  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(ptrDomain)}&type=PTR`;
  const response = await fetch(dohUrl, { headers: { Accept: "application/dns-json" } });
  const dnsData: any = await response.json();
  const ptrRecords = dnsData.Answer?.filter((a: any) => a.type === 12) || [];

  return {
    tool: "reverse-dns",
    timestamp: new Date().toISOString(),
    result: { ip, hostnames: ptrRecords.map((r: any) => r.data), found: ptrRecords.length > 0 },
  };
}

async function handlePortCheck(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const host = url.searchParams.get("host");
  const portStr = url.searchParams.get("port");
  if (!host || !portStr) throw new Error("Missing 'host' or 'port' parameter");

  const port = parseInt(portStr);
  if (port < 1 || port > 65535) throw new Error("Invalid port (must be 1-65535)");
  if (port === 25) {
    return { tool: "port-check", timestamp: new Date().toISOString(), result: { host, port, open: false, error: "Port 25 (SMTP) is blocked by Cloudflare Workers" } };
  }

  const startTime = performance.now();
  try {
    const socket = connect({ hostname: host, port });
    const writer = socket.writable.getWriter();
    await writer.write(new Uint8Array([0]));
    await writer.close();
    return { tool: "port-check", timestamp: new Date().toISOString(), result: { host, port, open: true, responseTime: Math.round(performance.now() - startTime) } };
  } catch (error) {
    return { tool: "port-check", timestamp: new Date().toISOString(), result: { host, port, open: false, error: error instanceof Error ? error.message : "Connection failed", responseTime: Math.round(performance.now() - startTime) } };
  }
}

async function handleASN(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const ip = url.searchParams.get("ip");
  const asn = url.searchParams.get("asn");

  if (!ip && !asn) throw new Error("Missing 'ip' or 'asn' parameter");

  try {
    let queryUrl: string;
    if (ip) {
      queryUrl = `https://api.bgpview.io/ip/${encodeURIComponent(ip)}`;
    } else {
      const asnNumber = asn!.replace(/^AS/i, "");
      queryUrl = `https://api.bgpview.io/asn/${asnNumber}`;
    }

    const response = await fetch(queryUrl, { signal: AbortSignal.timeout(10000) });
    const data: any = await response.json();

    return {
      tool: "asn",
      timestamp: new Date().toISOString(),
      result: ip ? {
        ip,
        asn: data.data?.asns?.[0]?.asn || "Unknown",
        asnName: data.data?.asns?.[0]?.name || "Unknown",
        country: data.data?.asns?.[0]?.country_code || "Unknown",
      } : {
        asn: `AS${data.data?.asn}`,
        name: data.data?.name || "Unknown",
        country: data.data?.country_code || "Unknown",
        prefixes: { ipv4: data.data?.ipv4_prefixes?.length || 0, ipv6: data.data?.ipv6_prefixes?.length || 0 },
      },
    };
  } catch (error) {
    return {
      tool: "asn",
      timestamp: new Date().toISOString(),
      result: { error: error instanceof Error ? error.message : "ASN lookup failed", note: "Using BGPView API - rate limited to 1 req/sec" },
    };
  }
}

async function handleBGP(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const prefix = url.searchParams.get("prefix") || url.searchParams.get("ip");
  if (!prefix) throw new Error("Missing 'prefix' or 'ip' parameter");

  try {
    const queryUrl = `https://api.bgpview.io/prefix/${encodeURIComponent(prefix)}`;
    const response = await fetch(queryUrl, { signal: AbortSignal.timeout(10000) });
    const data: any = await response.json();

    return {
      tool: "bgp",
      timestamp: new Date().toISOString(),
      result: {
        prefix: data.data?.prefix || prefix,
        asn: `AS${data.data?.asns?.[0]?.asn || "Unknown"}`,
        asnName: data.data?.asns?.[0]?.name || "Unknown",
        country: data.data?.asns?.[0]?.country_code || "Unknown",
        rirAllocation: data.data?.rir_allocation || "Unknown",
      },
    };
  } catch (error) {
    return {
      tool: "bgp",
      timestamp: new Date().toISOString(),
      result: { prefix, error: error instanceof Error ? error.message : "BGP lookup failed" },
    };
  }
}

async function handleDNSSEC(url: URL, env: Env, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const domain = url.searchParams.get("domain");
  if (!domain) throw new Error("Missing 'domain' parameter");

  const dohUrl = `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=DNSKEY&do=true`;
  const response = await fetch(dohUrl, { headers: { Accept: "application/dns-json" } });
  const dnsData: any = await response.json();

  const hasDNSSEC = dnsData.AD === true;
  const dnskeyRecords = dnsData.Answer?.filter((a: any) => a.type === 48) || [];

  return {
    tool: "dnssec",
    timestamp: new Date().toISOString(),
    result: {
      domain,
      dnssecEnabled: hasDNSSEC,
      authenticated: dnsData.AD || false,
      dnskeyCount: dnskeyRecords.length,
      status: hasDNSSEC ? "DNSSEC is enabled and validated" : "DNSSEC not enabled or not validated",
    },
  };
}

// ============= SEO & WEB TOOLS =============

async function handleRobotsTxt(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  if (!targetUrl) throw new Error("Missing 'url' parameter");

  try {
    const parsedUrl = new URL(targetUrl);
    const robotsUrl = `${parsedUrl.protocol}//${parsedUrl.hostname}/robots.txt`;
    const response = await fetch(robotsUrl, { signal: AbortSignal.timeout(10000) });

    if (!response.ok) {
      return { tool: "robots", timestamp: new Date().toISOString(), result: { url: robotsUrl, exists: false, status: response.status } };
    }

    const content = await response.text();
    const lines = content.split("\n");
    const userAgents = lines.filter(l => l.toLowerCase().startsWith("user-agent:")).map(l => l.split(":")[1].trim());
    const sitemaps = lines.filter(l => l.toLowerCase().startsWith("sitemap:")).map(l => l.split(":").slice(1).join(":").trim());
    const disallows = lines.filter(l => l.toLowerCase().startsWith("disallow:")).map(l => l.split(":")[1].trim());

    return {
      tool: "robots",
      timestamp: new Date().toISOString(),
      result: {
        url: robotsUrl,
        exists: true,
        size: content.length,
        lines: lines.length,
        userAgents: [...new Set(userAgents)],
        sitemaps,
        disallowRules: disallows.length,
        preview: content.substring(0, 500) + (content.length > 500 ? "..." : ""),
      },
    };
  } catch (error) {
    return { tool: "robots", timestamp: new Date().toISOString(), result: { error: error instanceof Error ? error.message : "Failed to fetch robots.txt" } };
  }
}

async function handleRedirects(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  const maxRedirects = Math.min(parseInt(url.searchParams.get("max") || "10"), 20);
  if (!targetUrl) throw new Error("Missing 'url' parameter");

  const chain = [];
  let currentUrl = targetUrl;
  let redirectCount = 0;

  for (let i = 0; i < maxRedirects; i++) {
    try {
      const startTime = performance.now();
      const response = await fetch(currentUrl, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(5000) });
      const responseTime = Math.round(performance.now() - startTime);

      chain.push({
        step: i + 1,
        url: currentUrl,
        status: response.status,
        location: response.headers.get("location") || null,
        responseTime,
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location) break;
        currentUrl = new URL(location, currentUrl).toString();
        redirectCount++;
      } else {
        break;
      }
    } catch (error) {
      chain.push({
        step: i + 1,
        url: currentUrl,
        error: error instanceof Error ? error.message : "Unknown error",
      });
      break;
    }
  }

  return {
    tool: "redirects",
    timestamp: new Date().toISOString(),
    result: {
      originalUrl: targetUrl,
      finalUrl: chain[chain.length - 1]?.url || targetUrl,
      redirectCount,
      chain,
      hasRedirectLoop: redirectCount >= maxRedirects,
    },
  };
}

async function handleMetaTags(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  if (!targetUrl) throw new Error("Missing 'url' parameter");

  try {
    const response = await fetch(targetUrl, { signal: AbortSignal.timeout(10000) });
    const html = await response.text();

    const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
    const descMatch = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']*)["']/i);
    const ogTitleMatch = html.match(/<meta\s+property=["']og:title["']\s+content=["']([^"']*)["']/i);
    const ogDescMatch = html.match(/<meta\s+property=["']og:description["']\s+content=["']([^"']*)["']/i);
    const ogImageMatch = html.match(/<meta\s+property=["']og:image["']\s+content=["']([^"']*)["']/i);

    return {
      tool: "meta-tags",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        title: titleMatch?.[1] || "Not found",
        description: descMatch?.[1] || "Not found",
        openGraph: {
          title: ogTitleMatch?.[1] || "Not found",
          description: ogDescMatch?.[1] || "Not found",
          image: ogImageMatch?.[1] || "Not found",
        },
      },
    };
  } catch (error) {
    return { tool: "meta-tags", timestamp: new Date().toISOString(), result: { url: targetUrl, error: error instanceof Error ? error.message : "Failed to fetch page" } };
  }
}

async function handleHTTPMethods(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  if (!targetUrl) throw new Error("Missing 'url' parameter");

  try {
    const response = await fetch(targetUrl, { method: "OPTIONS", signal: AbortSignal.timeout(10000) });
    const allow = response.headers.get("allow");
    const accessControlAllowMethods = response.headers.get("access-control-allow-methods");

    return {
      tool: "http-methods",
      timestamp: new Date().toISOString(),
      result: {
        url: targetUrl,
        allowHeader: allow || "Not specified",
        corsAllowMethods: accessControlAllowMethods || "Not specified",
        methods: allow ? allow.split(",").map(m => m.trim()) : [],
      },
    };
  } catch (error) {
    return { tool: "http-methods", timestamp: new Date().toISOString(), result: { url: targetUrl, error: error instanceof Error ? error.message : "Failed to check methods" } };
  }
}

async function handleSitemap(url: URL, ctx: ExecutionContext): Promise<Partial<ToolResponse>> {
  const targetUrl = url.searchParams.get("url");
  if (!targetUrl) throw new Error("Missing 'url' parameter");

  try {
    const parsedUrl = new URL(targetUrl);
    const sitemapUrl = targetUrl.endsWith(".xml") ? targetUrl : `${parsedUrl.protocol}//${parsedUrl.hostname}/sitemap.xml`;
    const response = await fetch(sitemapUrl, { signal: AbortSignal.timeout(10000) });

    if (!response.ok) {
      return { tool: "sitemap", timestamp: new Date().toISOString(), result: { url: sitemapUrl, exists: false, status: response.status } };
    }

    const content = await response.text();
    const urlMatches = content.match(/<loc>([^<]+)<\/loc>/g) || [];
    const urls = urlMatches.map(m => m.replace(/<\/?loc>/g, ""));

    return {
      tool: "sitemap",
      timestamp: new Date().toISOString(),
      result: {
        url: sitemapUrl,
        exists: true,
        urlCount: urls.length,
        urls: urls.slice(0, 100),
        hasMore: urls.length > 100,
      },
    };
  } catch (error) {
    return { tool: "sitemap", timestamp: new Date().toISOString(), result: { error: error instanceof Error ? error.message : "Failed to fetch sitemap" } };
  }
}

// ============= DEVELOPMENT TOOLS =============

function handleSubnet(url: URL): Partial<ToolResponse> {
  const cidr = url.searchParams.get("cidr");
  if (!cidr) throw new Error("Missing 'cidr' parameter");

  const [ip, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr);
  if (prefix < 0 || prefix > 32) throw new Error("Invalid CIDR prefix");

  const ipParts = ip.split(".").map(Number);
  const ipInt = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
  const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  const totalHosts = Math.pow(2, 32 - prefix);

  const intToIP = (int: number) => [(int >>> 24) & 0xFF, (int >>> 16) & 0xFF, (int >>> 8) & 0xFF, int & 0xFF].join(".");

  return {
    tool: "subnet",
    timestamp: new Date().toISOString(),
    result: {
      cidr,
      network: intToIP(network),
      broadcast: intToIP(broadcast),
      netmask: intToIP(mask),
      wildcardMask: intToIP(~mask >>> 0),
      firstHost: intToIP(network + 1),
      lastHost: intToIP(broadcast - 1),
      totalHosts,
      usableHosts: totalHosts - 2,
      prefix,
    },
  };
}

function handleBase64(url: URL): Partial<ToolResponse> {
  const operation = url.searchParams.get("op") || "encode";
  const input = url.searchParams.get("input");
  if (!input) throw new Error("Missing 'input' parameter");

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

  return { tool: "base64", timestamp: new Date().toISOString(), result: { operation, input: input.substring(0, 100), output: result } };
}

async function handleHash(url: URL): Promise<Partial<ToolResponse>> {
  const input = url.searchParams.get("input");
  const algorithm = url.searchParams.get("algo") || "SHA-256";
  if (!input) throw new Error("Missing 'input' parameter");

  const validAlgos = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
  if (!validAlgos.includes(algorithm)) throw new Error(`Invalid algorithm (use: ${validAlgos.join(", ")})`);

  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hash = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

  return { tool: "hash", timestamp: new Date().toISOString(), result: { input: input.substring(0, 100), algorithm, hash } };
}

function handleJWT(url: URL): Partial<ToolResponse> {
  const token = url.searchParams.get("token");
  if (!token) throw new Error("Missing 'token' parameter");

  try {
    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");

    const decodeBase64Url = (str: string) => {
      const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
      const decoded = atob(base64);
      return JSON.parse(decoded);
    };

    const header = decodeBase64Url(parts[0]);
    const payload = decodeBase64Url(parts[1]);

    return {
      tool: "jwt",
      timestamp: new Date().toISOString(),
      result: {
        header,
        payload,
        signature: parts[2],
        note: "This tool only decodes JWTs, it does not verify signatures",
      },
    };
  } catch (error) {
    throw new Error("Invalid JWT token");
  }
}

function handleJSONValidate(url: URL): Partial<ToolResponse> {
  const json = url.searchParams.get("json");
  if (!json) throw new Error("Missing 'json' parameter");

  try {
    const parsed = JSON.parse(json);
    return {
      tool: "json-validate",
      timestamp: new Date().toISOString(),
      result: {
        valid: true,
        formatted: JSON.stringify(parsed, null, 2),
        type: Array.isArray(parsed) ? "array" : typeof parsed,
        size: json.length,
      },
    };
  } catch (error) {
    return {
      tool: "json-validate",
      timestamp: new Date().toISOString(),
      result: {
        valid: false,
        error: error instanceof Error ? error.message : "Invalid JSON",
      },
    };
  }
}

function handlePunycode(url: URL): Partial<ToolResponse> {
  const input = url.searchParams.get("input");
  const operation = url.searchParams.get("op") || "encode";
  if (!input) throw new Error("Missing 'input' parameter");

  try {
    let result: string;
    if (operation === "encode") {
      const url = new URL(`http://${input}`);
      result = url.hostname;
    } else if (operation === "decode") {
      if (!input.includes("xn--")) {
        result = input;
      } else {
        const url = new URL(`http://${input}`);
        result = decodeURIComponent(url.hostname);
      }
    } else {
      throw new Error("Invalid operation (use 'encode' or 'decode')");
    }

    return {
      tool: "punycode",
      timestamp: new Date().toISOString(),
      result: { operation, input, output: result },
    };
  } catch (error) {
    throw new Error("Invalid domain name");
  }
}

function handleURLParse(url: URL): Partial<ToolResponse> {
  const targetUrl = url.searchParams.get("url");
  if (!targetUrl) throw new Error("Missing 'url' parameter");

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

function handleUserAgent(request: Request): Partial<ToolResponse> {
  const ua = request.headers.get("user-agent") || "unknown";
  const isMobile = /mobile/i.test(ua);
  const isTablet = /tablet|ipad/i.test(ua);
  const isBot = /bot|crawler|spider/i.test(ua);

  let browser = "unknown";
  if (/chrome/i.test(ua) && !/edg/i.test(ua)) browser = "Chrome";
  else if (/safari/i.test(ua) && !/chrome/i.test(ua)) browser = "Safari";
  else if (/firefox/i.test(ua)) browser = "Firefox";
  else if (/edg/i.test(ua)) browser = "Edge";

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

// ============= HELPERS =============

function getAllToolPaths(): string[] {
  return [
    "/dns", "/http-check", "/ip-info", "/headers", "/ping",
    "/ssl", "/spf", "/dmarc", "/security-headers", "/hsts-preload", "/caa",
    "/whois", "/http-version", "/reverse-dns", "/port-check", "/asn", "/bgp", "/dnssec",
    "/robots", "/redirects", "/meta-tags", "/http-methods", "/sitemap",
    "/subnet", "/base64", "/hash", "/jwt", "/json-validate", "/punycode",
    "/url-parse", "/user-agent",
  ];
}

function handleHomePage(corsHeaders: Record<string, string>): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ultimate Network Tools - 28 Professional Diagnostic Tools</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.6;
      color: #333;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 20px;
    }
    .container {
      max-width: 1400px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      padding: 40px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    h1 {
      color: #667eea;
      font-size: 2.8rem;
      margin-bottom: 10px;
      text-align: center;
    }
    .subtitle {
      text-align: center;
      color: #666;
      margin-bottom: 40px;
      font-size: 1.2rem;
    }
    .category {
      margin-top: 40px;
    }
    .category-title {
      font-size: 1.8rem;
      color: #764ba2;
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 3px solid #667eea;
    }
    .tools-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 15px;
    }
    .tool-card {
      background: #f8f9fa;
      border: 2px solid #e9ecef;
      border-radius: 8px;
      padding: 15px;
      transition: all 0.3s;
    }
    .tool-card:hover {
      border-color: #667eea;
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(102,126,234,0.2);
    }
    .tool-title {
      font-size: 1.1rem;
      color: #667eea;
      margin-bottom: 8px;
      font-weight: 600;
    }
    .tool-path {
      background: #667eea;
      color: white;
      padding: 3px 6px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.85rem;
      display: inline-block;
    }
    .badge {
      display: inline-block;
      background: #28a745;
      color: white;
      padding: 6px 15px;
      border-radius: 15px;
      font-size: 0.9rem;
      margin-left: 10px;
      font-weight: bold;
    }
    .footer {
      margin-top: 50px;
      padding-top: 30px;
      border-top: 2px solid #e9ecef;
      text-align: center;
      color: #666;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛰️ Ultimate Network Tools Suite</h1>
    <p class="subtitle">Professional-grade diagnostic & development tools <span class="badge">28 Tools</span></p>

    <div class="category">
      <h2 class="category-title">Core Network (5)</h2>
      <div class="tools-grid">
        <div class="tool-card"><div class="tool-title">DNS Lookup</div><div class="tool-path">/dns?domain=example.com</div></div>
        <div class="tool-card"><div class="tool-title">HTTP/HTTPS Checker</div><div class="tool-path">/http-check?url=...</div></div>
        <div class="tool-card"><div class="tool-title">IP Geolocation</div><div class="tool-path">/ip-info</div></div>
        <div class="tool-card"><div class="tool-title">Headers Inspector</div><div class="tool-path">/headers</div></div>
        <div class="tool-card"><div class="tool-title">Ping/Latency</div><div class="tool-path">/ping?url=...</div></div>
      </div>
    </div>

    <div class="category">
      <h2 class="category-title">Email & Security (6)</h2>
      <div class="tools-grid">
        <div class="tool-card"><div class="tool-title">SSL/TLS Certificate</div><div class="tool-path">/ssl?domain=...</div></div>
        <div class="tool-card"><div class="tool-title">SPF Checker</div><div class="tool-path">/spf?domain=...</div></div>
        <div class="tool-card"><div class="tool-title">DMARC Checker</div><div class="tool-path">/dmarc?domain=...</div></div>
        <div class="tool-card"><div class="tool-title">Security Headers</div><div class="tool-path">/security-headers?url=...</div></div>
        <div class="tool-card"><div class="tool-title">HSTS Preload Checker</div><div class="tool-path">/hsts-preload?domain=...</div></div>
        <div class="tool-card"><div class="tool-title">CAA Record Checker</div><div class="tool-path">/caa?domain=...</div></div>
      </div>
    </div>

    <div class="category">
      <h2 class="category-title">Advanced Network (7)</h2>
      <div class="tools-grid">
        <div class="tool-card"><div class="tool-title">WHOIS Lookup</div><div class="tool-path">/whois?domain=...</div></div>
        <div class="tool-card"><div class="tool-title">HTTP Version</div><div class="tool-path">/http-version?url=...</div></div>
        <div class="tool-card"><div class="tool-title">Reverse DNS</div><div class="tool-path">/reverse-dns?ip=...</div></div>
        <div class="tool-card"><div class="tool-title">Port Check</div><div class="tool-path">/port-check?host=...&port=...</div></div>
        <div class="tool-card"><div class="tool-title">ASN Lookup</div><div class="tool-path">/asn?ip=... or asn=...</div></div>
        <div class="tool-card"><div class="tool-title">BGP Route Info</div><div class="tool-path">/bgp?prefix=...</div></div>
        <div class="tool-card"><div class="tool-title">DNSSEC Validation</div><div class="tool-path">/dnssec?domain=...</div></div>
      </div>
    </div>

    <div class="category">
      <h2 class="category-title">SEO & Web Tools (5)</h2>
      <div class="tools-grid">
        <div class="tool-card"><div class="tool-title">Robots.txt Checker</div><div class="tool-path">/robots?url=...</div></div>
        <div class="tool-card"><div class="tool-title">Redirect Chain Analyzer</div><div class="tool-path">/redirects?url=...</div></div>
        <div class="tool-card"><div class="tool-title">Meta Tags Analyzer</div><div class="tool-path">/meta-tags?url=...</div></div>
        <div class="tool-card"><div class="tool-title">HTTP Methods Tester</div><div class="tool-path">/http-methods?url=...</div></div>
        <div class="tool-card"><div class="tool-title">Sitemap Parser</div><div class="tool-path">/sitemap?url=...</div></div>
      </div>
    </div>

    <div class="category">
      <h2 class="category-title">Development Tools (5)</h2>
      <div class="tools-grid">
        <div class="tool-card"><div class="tool-title">Base64 Encode/Decode</div><div class="tool-path">/base64?input=...&op=encode</div></div>
        <div class="tool-card"><div class="tool-title">Hash Generator</div><div class="tool-path">/hash?input=...&algo=SHA-256</div></div>
        <div class="tool-card"><div class="tool-title">JWT Decoder</div><div class="tool-path">/jwt?token=...</div></div>
        <div class="tool-card"><div class="tool-title">JSON Validator</div><div class="tool-path">/json-validate?json=...</div></div>
        <div class="tool-card"><div class="tool-title">Punycode Converter</div><div class="tool-path">/punycode?input=...</div></div>
      </div>
    </div>

    <div class="footer">
      <p><strong>⚡ Powered by Cloudflare Workers</strong></p>
      <p>Global edge deployment • Sub-50ms latency • Production-grade reliability</p>
      <p style="margin-top: 10px; font-size: 0.9rem;">Built following all Cloudflare Workers best practices</p>
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
