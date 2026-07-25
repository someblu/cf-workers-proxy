import { WorkerEntrypoint } from "cloudflare:workers";

const DEFAULT_PROXY_HOSTNAME = "github.com";
const DEFAULT_PROXY_PROTOCOL = "https";
const DEFAULT_RELEASE_PATHNAME_REGEX =
  "^/[^/]+/[^/]+/releases/download/[^/]+/.+";
const DEFAULT_GITHUB_RAW_PATHNAME_REGEX = "^/[^/]+/[^/]+/raw/.+";
const HSTS_HEADER_VALUE = "max-age=31536000";

// Workers Cache TTL（秒）
const RELEASE_CACHE_TTL = 2592000; // 30 天：release 资源按 tag 发布，基本不变
const RAW_CACHE_TTL = 300; // 5 分钟：raw 指向分支，内容会变
const RAW_COMMIT_CACHE_TTL = 2592000; // 30 天：40 位 commit SHA 不可变

const SENSITIVE_REQUEST_HEADERS = [
  "cookie",
  "host",
  "origin",
  "referer",
  "x-csrf-token",
  "x-github-otp",
  "x-requested-with",
];
const CLIENT_FORWARDING_HEADERS = [
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "cdn-loop",
  "forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-port",
  "x-forwarded-proto",
  "x-real-ip",
  "true-client-ip",
];
const STRIP_RESPONSE_HEADERS = [
  "set-cookie",
  "set-cookie2",
  "x-github-request-id",
  "x-served-by",
  "x-fastly-request-id",
  "via",
  "x-cache",
  "x-cache-hits",
  "x-timer",
  "x-pjax-url",
  "content-security-policy",
  "content-security-policy-report-only",
  "report-to",
  "nel",
];

function logError(request, message) {
  console.error(
    `${message}, clientIp: ${request.headers.get(
      "cf-connecting-ip",
    )}, user-agent: ${request.headers.get("user-agent")}, url: ${request.url}`,
  );
}

function normalizeProtocol(protocol) {
  return protocol.endsWith(":") ? protocol : `${protocol}:`;
}

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("strict-transport-security", HSTS_HEADER_VALUE);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function textResponse(status, body, headers = {}) {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("cache-control", "no-store");
  return withSecurityHeaders(
    new Response(body, { status, headers: responseHeaders }),
  );
}

function headerValue(request, name) {
  return request.headers.get(name) || "";
}

function matchesRegex(value, regex) {
  return regex && new RegExp(regex).test(value);
}

function accessFilterRejected(request, env) {
  const {
    UA_WHITELIST_REGEX,
    UA_BLACKLIST_REGEX,
    IP_WHITELIST_REGEX,
    IP_BLACKLIST_REGEX,
    REGION_WHITELIST_REGEX,
    REGION_BLACKLIST_REGEX,
  } = env;
  const ua = headerValue(request, "user-agent").toLowerCase();
  const ip = headerValue(request, "cf-connecting-ip");
  const region = headerValue(request, "cf-ipcountry");

  return (
    (UA_WHITELIST_REGEX && !matchesRegex(ua, UA_WHITELIST_REGEX)) ||
    (UA_BLACKLIST_REGEX && matchesRegex(ua, UA_BLACKLIST_REGEX)) ||
    (IP_WHITELIST_REGEX && !matchesRegex(ip, IP_WHITELIST_REGEX)) ||
    (IP_BLACKLIST_REGEX && matchesRegex(ip, IP_BLACKLIST_REGEX)) ||
    (REGION_WHITELIST_REGEX && !matchesRegex(region, REGION_WHITELIST_REGEX)) ||
    (REGION_BLACKLIST_REGEX && matchesRegex(region, REGION_BLACKLIST_REGEX))
  );
}

function stripRequestHeaders(headers) {
  for (const header of SENSITIVE_REQUEST_HEADERS) {
    headers.delete(header);
  }
  for (const header of CLIENT_FORWARDING_HEADERS) {
    headers.delete(header);
  }
}

function stripResponseHeaders(headers) {
  for (const header of STRIP_RESPONSE_HEADERS) {
    headers.delete(header);
  }
}

function selectTarget(url, env) {
  const {
    PROXY_HOSTNAME = DEFAULT_PROXY_HOSTNAME,
    PROXY_PROTOCOL = DEFAULT_PROXY_PROTOCOL,
    RELEASE_PATHNAME_REGEX = DEFAULT_RELEASE_PATHNAME_REGEX,
    GITHUB_RAW_PATHNAME_REGEX = DEFAULT_GITHUB_RAW_PATHNAME_REGEX,
  } = env;

  if (
    matchesRegex(url.pathname, RELEASE_PATHNAME_REGEX) ||
    matchesRegex(url.pathname, GITHUB_RAW_PATHNAME_REGEX)
  ) {
    const targetUrl = new URL(url.toString());
    targetUrl.hostname = PROXY_HOSTNAME;
    targetUrl.protocol = normalizeProtocol(PROXY_PROTOCOL);
    return targetUrl;
  }

  return null;
}

// 认证：客户端自带 Authorization 优先透传；否则注入服务端统一 GITHUB_TOKEN。
// token 仅用于向 github.com 首请求；跨源跟随 302 到 objects/codeload 签名 URL 时，
// fetch 按规范会自动剥离 Authorization，不会把 token 泄露给对象存储。
function applyAuthorization(headers, env) {
  if (headers.has("authorization")) {
    return;
  }
  if (env.GITHUB_TOKEN) {
    headers.set("authorization", `Bearer ${env.GITHUB_TOKEN}`);
  }
}

function isReleasePath(url, env) {
  return matchesRegex(
    url.pathname,
    env.RELEASE_PATHNAME_REGEX || DEFAULT_RELEASE_PATHNAME_REGEX,
  );
}

function isRawCommitPath(url) {
  return /^\/[^/]+\/[^/]+\/raw\/[a-f0-9]{40}\//i.test(url.pathname);
}

function cacheTtl(url, env) {
  if (isReleasePath(url, env)) return RELEASE_CACHE_TTL;
  if (isRawCommitPath(url)) return RAW_COMMIT_CACHE_TTL;
  return RAW_CACHE_TTL;
}

function setDownstreamCacheControl(
  headers,
  url,
  env,
  clientAuthenticated,
  method,
  status,
) {
  if (
    clientAuthenticated ||
    (method !== "GET" && method !== "HEAD") ||
    status < 200 ||
    status >= 300
  ) {
    headers.set("cache-control", "private, no-store");
    return;
  }

  const ttl = cacheTtl(url, env);
  headers.set("cache-control", `public, max-age=${ttl}`);
}

async function proxyRequest(request, env) {
  const targetUrl = new URL(request.url);
  // ctx.exports loopback 会把 named entrypoint 的 URL 呈现为 http://；
  // 在注入 GitHub token 前恢复目标协议，避免重定向时剥离 Authorization。
  targetUrl.protocol = normalizeProtocol(
    env.PROXY_PROTOCOL || DEFAULT_PROXY_PROTOCOL,
  );
  targetUrl.port = "";

  const isHead = request.method === "HEAD";
  const clientAuthenticated = request.headers.has("authorization");
  const headers = new Headers(request.headers);
  stripRequestHeaders(headers);
  applyAuthorization(headers, env);

  const init = {
    method: request.method,
    headers,
    redirect: "follow",
  };

  const upstreamResponse = await fetch(new Request(targetUrl.toString(), init));
  const responseHeaders = new Headers(upstreamResponse.headers);
  stripResponseHeaders(responseHeaders);

  setDownstreamCacheControl(
    responseHeaders,
    targetUrl,
    env,
    clientAuthenticated,
    request.method,
    upstreamResponse.status,
  );

  return withSecurityHeaders(
    new Response(isHead ? null : upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders,
    }),
  );
}

// Workers Cache 位于此 entrypoint 之前。命中时不会执行 GitHub fetch。
export class CachedGitHubProxy extends WorkerEntrypoint {
  async fetch(request) {
    return proxyRequest(request, this.env);
  }
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      if (url.protocol === "http:") {
        url.protocol = "https:";
        return withSecurityHeaders(Response.redirect(url.toString(), 301));
      }

      if (request.method !== "GET" && request.method !== "HEAD") {
        logError(request, "Rejected 405");
        return textResponse(405, "Method Not Allowed", { Allow: "GET, HEAD" });
      }

      if (accessFilterRejected(request, env)) {
        logError(request, "Rejected by access filter");
        return textResponse(404, "Not Found");
      }

      const targetUrl = selectTarget(url, env);
      if (!targetUrl) {
        logError(request, "Rejected path");
        return textResponse(404, "Not Found");
      }

      // 客户端 token 可能访问私有内容，完全绕过内部缓存。
      if (request.headers.has("authorization")) {
        return await proxyRequest(
          new Request(targetUrl, {
            method: request.method,
            headers: request.headers,
          }),
          env,
        );
      }

      const headers = new Headers(request.headers);
      stripRequestHeaders(headers);
      headers.delete("authorization");

      // Workers Cache 默认不包含 hostname；显式加入目标 host，支持安全地
      // 调整 PROXY_HOSTNAME，并保留 path/query 作为资源身份。
      const cacheKey = `/${targetUrl.hostname}${targetUrl.pathname}${targetUrl.search}`;
      const cachedRequest = new Request(targetUrl, {
        method: request.method,
        headers,
      });
      return await ctx.exports.CachedGitHubProxy.fetch(cachedRequest, {
        cf: { cacheKey },
      });
    } catch (error) {
      logError(request, `Fetch error: ${error.message}`);
      return textResponse(500, "Internal Server Error");
    }
  },
};
