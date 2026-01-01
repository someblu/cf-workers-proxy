const DEFAULT_PROXY_HOSTNAME = "github.com";
const DEFAULT_PROXY_PROTOCOL = "https";
const DEFAULT_RELEASE_PATHNAME_REGEX =
  "^/[^/]+/[^/]+/releases/download/[^/]+/.+";
const DEFAULT_GITHUB_RAW_PATHNAME_REGEX = "^/[^/]+/[^/]+/raw/.+";
const HSTS_HEADER_VALUE = "max-age=31536000";

// 边缘缓存 TTL（秒）
const RELEASE_CACHE_TTL = 2592000; // 30 天：release 资源按 tag 发布，基本不变
const RAW_CACHE_TTL = 300; // 5 分钟：raw 指向分支，内容会变

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
  "x-real-ip",
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
      "cf-connecting-ip"
    )}, user-agent: ${request.headers.get("user-agent")}, url: ${request.url}`
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
    new Response(body, { status, headers: responseHeaders })
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
    env.RELEASE_PATHNAME_REGEX || DEFAULT_RELEASE_PATHNAME_REGEX
  );
}

// 边缘缓存选项（fetch 的 cf 字段）。
// release 下载资源按 tag 发布、内容基本不变 → 长缓存；raw 指向分支 → 短缓存。
// 客户端自带 token 的请求可能拉取私有内容，一律不缓存，避免私有响应被其他用户命中。
// HEAD 不写缓存（cacheTtl:0 且不 cacheEverything），但仍可命中 GET 已写入的
// 缓存条目——探活不额外占用缓存。
function cacheOptions(url, env, clientAuthenticated, isHead) {
  if (clientAuthenticated || isHead) {
    return { cacheTtl: 0 };
  }
  if (isReleasePath(url, env)) {
    return { cacheEverything: true, cacheTtl: RELEASE_CACHE_TTL };
  }
  return { cacheEverything: true, cacheTtl: RAW_CACHE_TTL };
}

function setDownstreamCacheControl(
  headers,
  url,
  env,
  clientAuthenticated,
  isHead,
  status
) {
  if (clientAuthenticated || isHead || status < 200 || status >= 300) {
    headers.set("cache-control", "private, no-store");
    return;
  }

  const ttl = isReleasePath(url, env) ? RELEASE_CACHE_TTL : RAW_CACHE_TTL;
  headers.set("cache-control", `public, max-age=${ttl}`);
}

async function proxyRequest(request, targetUrl, env) {
  const isHead = request.method === "HEAD";
  const clientAuthenticated = request.headers.has("authorization");
  const headers = new Headers(request.headers);
  stripRequestHeaders(headers);
  applyAuthorization(headers, env);

  // 仅 release asset 的 HEAD 需要 workaround：CF 运行时里 method:HEAD 的子请求
  // 命中 release GET 写入的 cacheEverything 条目时会返回 401（配置层 cacheTtl:0
  // 无法绕过，问题在读取那一刻）。raw 的 HEAD 无此问题，保持原样透传。
  const headAsGet = isHead && isReleasePath(targetUrl, env);
  // 转 GET 时用 Range: bytes=0-0 只探首字节，省上游/Worker 带宽；仅在客户端
  // 未自带 Range 时启用，之后把 206 归一成 200（content-length 用完整文件大小）。
  const rangeProbe = headAsGet && !headers.has("range");
  if (rangeProbe) {
    headers.set("range", "bytes=0-0");
  }

  const init = {
    method: headAsGet ? "GET" : request.method,
    headers,
    redirect: "follow",
    cf: cacheOptions(targetUrl, env, clientAuthenticated, isHead),
  };

  const upstreamResponse = await fetch(new Request(targetUrl.toString(), init));
  const responseHeaders = new Headers(upstreamResponse.headers);
  stripResponseHeaders(responseHeaders);

  let status = upstreamResponse.status;
  let statusText = upstreamResponse.statusText;

  // 把 Range 探测的 206 归一成一个“真 HEAD”式的 200：
  // content-length 取 Content-Range 里的完整大小（bytes 0-0/1856 → 1856），删掉 content-range。
  if (rangeProbe && status === 206) {
    const contentRange = responseHeaders.get("content-range");
    const total = contentRange && contentRange.match(/\/(\d+)\s*$/);
    if (total) {
      responseHeaders.set("content-length", total[1]);
    } else {
      responseHeaders.delete("content-length");
    }
    responseHeaders.delete("content-range");
    status = 200;
    statusText = "OK";
  }

  setDownstreamCacheControl(
    responseHeaders,
    targetUrl,
    env,
    clientAuthenticated,
    isHead,
    status
  );

  return withSecurityHeaders(
    new Response(isHead ? null : upstreamResponse.body, {
      status,
      statusText,
      headers: responseHeaders,
    })
  );
}

export default {
  async fetch(request, env) {
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

      return await proxyRequest(request, targetUrl, env);
    } catch (error) {
      logError(request, `Fetch error: ${error.message}`);
      return textResponse(500, "Internal Server Error");
    }
  },
};
