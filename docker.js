// docker.js —— Docker Registry 拉取代理（部署于 docker-proxy 分支 → docker.suzu.sh）
//
// 设计边界（pull-only 镜像拉取代理，不是通用 HTTP 代理）：
//   - 仅放行 /v2 路径与 GET/HEAD/OPTIONS 方法，其余一律 404 / 405（fail-closed）；
//   - 按上游返回的 401 WWW-Authenticate challenge 动态取 token，支持多 registry；
//     多 registry 用法：docker pull docker.suzu.sh/ghcr.io/owner/repo（路径前缀），
//     或子域 ghcr.docker.suzu.sh、或 ?ns=（供 containerd/mirror 使用）；
//   - 不转发客户端 Authorization / Cookie；服务端凭据（DOCKERHUB_*、GHCR_*）仅在
//     upstreamHost 为对应可信 registry 时使用，提升拉取额度且防 confused-deputy；
//   - 无 module-global 可变状态，所有上游解析均为 request-local；
//   - 响应头脱敏（保留 registry 协议头），根路径 / 浏览器无网页入口。

const HSTS_HEADER_VALUE = "max-age=31536000";
const DEFAULT_UPSTREAM = "registry-1.docker.io";
const DEFAULT_BLOCKED_UA = ["netcraft"];
const ALLOWED_METHODS = ["GET", "HEAD", "OPTIONS"];

// 边缘缓存 TTL（秒）。blob 按 digest 内容寻址、不可变 → 长缓存。
// manifest 的同一 URL 会按 Accept 返回不同 media type；在 cache key
// 显式区分 Accept 前不缓存，避免向客户端返回错误格式。
const BLOB_CACHE_TTL = 2592000; // 30 天

// 子域前缀 → registry 上游
const REGISTRY_ROUTES = {
  quay: "quay.io",
  gcr: "gcr.io",
  "k8s-gcr": "k8s.gcr.io",
  k8s: "registry.k8s.io",
  ghcr: "ghcr.io",
  cloudsmith: "docker.cloudsmith.io",
  nvcr: "nvcr.io",
};

// 响应头指纹脱敏清单：删除暴露上游/CDN 身份的头。
// 绝不能包含 registry 协议语义头：
//   www-authenticate / docker-content-digest / docker-distribution-api-version /
//   content-range / accept-ranges / content-length / location
const STRIP_RESPONSE_HEADERS = [
  "content-security-policy",
  "content-security-policy-report-only",
  "clear-site-data",
  "report-to",
  "nel",
  "x-fastly-request-id",
  "x-served-by",
  "x-cache",
  "x-cache-hits",
  "x-timer",
];

const PREFLIGHT_HEADERS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,HEAD,OPTIONS",
  "access-control-allow-headers": "Authorization,Accept,Range",
  "access-control-max-age": "1728000",
  "cache-control": "no-store",
};

function logError(request, message) {
  console.error(
    `${message}, clientIp: ${request.headers.get(
      "cf-connecting-ip"
    )}, user-agent: ${request.headers.get("user-agent")}, url: ${request.url}`
  );
}

function headerValue(request, name) {
  return request.headers.get(name) || "";
}

function matchesRegex(value, regex) {
  return regex && new RegExp(regex).test(value);
}

// 解析 env.UA 追加的屏蔽 UA（request-local，不改全局状态）
function parseEnvUA(envUA) {
  if (!envUA) return [];
  return envUA
    .replace(/[\t "'\r\n]+/g, ",")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

// 已知 registry 主机白名单（用于路径前缀路由的合法性校验）
const KNOWN_REGISTRY_HOSTS = new Set([
  DEFAULT_UPSTREAM,
  "docker.io",
  ...Object.values(REGISTRY_ROUTES),
]);

// 解析目标上游 registry 与重写后的 registry 路径（request-local）。
// 优先级：路径前缀 /v2/<registry-host>/... > ns 参数 > 子域路由 > 默认 docker hub。
// 路径前缀是 `docker pull docker.suzu.sh/ghcr.io/owner/repo` 的可行用法
// （docker CLI 不接受 ?ns= 查询串）。
function resolveUpstream(url) {
  // 路径前缀路由：/v2/<host>/rest，且 <host> 是白名单内 registry
  const m = url.pathname.match(/^\/v2\/([^/]+)\/(.+)$/);
  if (m && KNOWN_REGISTRY_HOSTS.has(m[1])) {
    const host = m[1] === "docker.io" ? DEFAULT_UPSTREAM : m[1];
    return { host, pathname: `/v2/${m[2]}` };
  }

  const ns = url.searchParams.get("ns");
  if (ns) {
    if (!KNOWN_REGISTRY_HOSTS.has(ns)) return null;
    const host = ns === "docker.io" ? DEFAULT_UPSTREAM : ns;
    return { host, pathname: url.pathname };
  }

  const hostTop = (url.searchParams.get("hubhost") || url.hostname).split(
    "."
  )[0];
  if (hostTop in REGISTRY_ROUTES) {
    return { host: REGISTRY_ROUTES[hostTop], pathname: url.pathname };
  }

  return { host: DEFAULT_UPSTREAM, pathname: url.pathname };
}

// 边缘缓存选项（fetch 的 cf 字段）。
// 仅对 blob 缓存；manifest、/v2/ 探测与其它请求不缓存。
function cacheOptions(pathname) {
  if (pathname.includes("/blobs/")) {
    return { cacheEverything: true, cacheTtl: BLOB_CACHE_TTL };
  }
  return { cacheTtl: 0 };
}

// 可选访问过滤：命中即拒绝（404）。默认全空 = 不启用。
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

// 仅保留拉取所需请求头；剥离客户端凭据、原始 host 与转发指纹头。
// 删除 host：否则上游 registry 会收到 docker.suzu.sh，导致 400/404 或鉴权 challenge 不匹配。
// fetch() 会按目标 URL 的 hostname 自动生成正确的 Host。
function buildForwardHeaders(request) {
  const headers = new Headers(request.headers);
  for (const h of [
    "authorization",
    "cookie",
    "host",
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cdn-loop",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "true-client-ip",
  ]) {
    headers.delete(h);
  }
  return headers;
}

// 解析 WWW-Authenticate: Bearer realm="...",service="...",scope="..."
function parseAuthenticate(header) {
  const out = {};
  const re = /(\w+)="([^"]*)"/g;
  let m;
  while ((m = re.exec(header)) !== null) {
    out[m[1]] = m[2];
  }
  return out;
}

// 可信 upstream registry → { 允许的 realm 主机, 凭据 env 键 }。
// 凭据绑定到「解析出的可信 upstreamHost」，而非上游返回的 realm，防止 confused-deputy：
// 恶意 registry 无法通过返回 realm="auth.docker.io" 骗取你的 DockerHub 凭据。
const TRUSTED_CREDENTIALS = {
  "registry-1.docker.io": {
    realmHost: "auth.docker.io",
    userKey: "DOCKERHUB_USERNAME",
    secretKey: "DOCKERHUB_TOKEN",
  },
  "ghcr.io": {
    realmHost: "ghcr.io",
    userKey: "GHCR_USERNAME",
    secretKey: "GHCR_TOKEN",
  },
};

// 仅当 (1) upstreamHost 是可信 registry，(2) 上游返回的 realm 主机与该 registry 的
// 预期 realm 完全一致，(3) 对应凭据已配置时，才返回 Basic 认证。任一不满足 → null（匿名）。
function credentialFor(upstreamHost, realmHost, env) {
  const trusted = TRUSTED_CREDENTIALS[upstreamHost];
  if (!trusted || trusted.realmHost !== realmHost) return null;
  const user = env[trusted.userKey];
  const secret = env[trusted.secretKey];
  if (!user || !secret) return null;
  return `Basic ${btoa(`${user}:${secret}`)}`;
}

// 按 challenge 动态向上游 realm 取 token（支持任意 registry）。
// 仅在 upstreamHost 可信且 realm 匹配时，才用服务端凭据换 token（提升额度）。
async function fetchUpstreamToken(parsed, request, env, upstreamHost) {
  if (!parsed.realm) return null;
  const tokenUrl = new URL(parsed.realm);
  if (parsed.service) tokenUrl.searchParams.set("service", parsed.service);
  if (parsed.scope) tokenUrl.searchParams.set("scope", parsed.scope);
  const headers = {
    "User-Agent": headerValue(request, "user-agent"),
    Accept: "application/json",
  };
  const credential = credentialFor(upstreamHost, tokenUrl.hostname, env);
  if (credential) headers.Authorization = credential;
  const res = await fetch(tokenUrl.toString(), { headers });
  if (!res.ok) return { token: null, usedCredential: false };
  const data = await res.json().catch(() => null);
  const token = (data && (data.token || data.access_token)) || null;
  return { token, usedCredential: Boolean(credential) };
}

// 统一出站：脱敏指纹头 + HSTS + CORS，保留 body/status 与 registry 协议头
function finalize(response, pathname, method, clientAuthenticated) {
  const headers = new Headers(response.headers);
  for (const h of STRIP_RESPONSE_HEADERS) headers.delete(h);
  headers.set("strict-transport-security", HSTS_HEADER_VALUE);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-expose-headers", "*");

  if (pathname.includes("/manifests/")) {
    const vary = headers.get("vary");
    const values = new Set(
      (vary || "")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean)
    );
    values.add("Accept");
    headers.set("vary", [...values].join(", "));
  }

  const cacheableBlob =
    method === "GET" &&
    !clientAuthenticated &&
    response.status >= 200 &&
    response.status < 300 &&
    pathname.includes("/blobs/");
  headers.set(
    "cache-control",
    cacheableBlob ? `public, max-age=${BLOB_CACHE_TTL}` : "private, no-store"
  );

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function plain(status, body) {
  const headers = new Headers({ "content-type": "text/plain; charset=utf-8" });
  headers.set("strict-transport-security", HSTS_HEADER_VALUE);
  headers.set("cache-control", "no-store");
  return new Response(body, { status, headers });
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      // http → https
      if (url.protocol === "http:") {
        url.protocol = "https:";
        return new Response(null, {
          status: 301,
          headers: {
            location: url.toString(),
            "strict-transport-security": HSTS_HEADER_VALUE,
            "cache-control": "no-store",
          },
        });
      }

      // 方法限制：pull-only
      if (!ALLOWED_METHODS.includes(request.method)) {
        logError(request, "Rejected 405");
        const res = plain(405, "Method Not Allowed");
        const headers = new Headers(res.headers);
        headers.set("Allow", "GET, HEAD, OPTIONS");
        return new Response(res.body, { status: 405, headers });
      }

      // CORS 预检
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: PREFLIGHT_HEADERS });
      }

      // 屏蔽爬虫 UA（request-local）
      const ua = headerValue(request, "user-agent").toLowerCase();
      const blockedUAs = DEFAULT_BLOCKED_UA.concat(parseEnvUA(env.UA));
      if (blockedUAs.some((b) => ua.includes(b))) {
        return plain(404, "Not Found");
      }

      // 可选访问过滤
      if (accessFilterRejected(request, env)) {
        logError(request, "Rejected by access filter");
        return plain(404, "Not Found");
      }

      // fail-closed 路径限制：仅 /v2，其余（含根路径、浏览器网页）一律 404
      if (url.pathname !== "/v2" && !url.pathname.startsWith("/v2/")) {
        return plain(404, "Not Found");
      }

      // 解析上游与 registry 路径（request-local）
      const upstream = resolveUpstream(url);
      if (!upstream) {
        logError(request, "Rejected unknown registry namespace");
        return plain(404, "Not Found");
      }
      const { host: upstreamHost, pathname: resolvedPath } = upstream;

      // docker hub 裸镜像名自动补全 /v2/library/
      let pathname = resolvedPath;
      if (
        upstreamHost === DEFAULT_UPSTREAM &&
        /^\/v2\/[^/]+\/[^/]+\/[^/]+$/.test(pathname) &&
        !/^\/v2\/library\//.test(pathname)
      ) {
        pathname = "/v2/library/" + pathname.slice("/v2/".length);
      }

      const upstreamUrl = new URL(url.toString());
      upstreamUrl.protocol = "https:";
      upstreamUrl.hostname = upstreamHost;
      upstreamUrl.port = "";
      upstreamUrl.pathname = pathname;
      // 删除代理侧路由控制参数：非 API 参数，转发给上游可能被拒，也会污染缓存 key。
      upstreamUrl.searchParams.delete("ns");
      upstreamUrl.searchParams.delete("hubhost");

      // 缓存策略：仅 blob 内容寻址不可变，长缓存；其它请求不缓存。
      // 关键：匿名首请求（challenge 探测）不缓存，否则 401 会被缓存导致鉴权永远失败；
      // 只有带 token 的成功响应才进边缘缓存。
      const cfCache = cacheOptions(pathname);

      // 匿名首请求：challenge 探测，必然可能返回 401，强制不缓存。
      const clientAuthenticated = request.headers.has("authorization");
      const forwardHeaders = buildForwardHeaders(request);
      let response = await fetch(
        new Request(upstreamUrl, {
          method: request.method,
          headers: forwardHeaders,
          redirect: "follow",
          cf: { cacheTtl: 0 },
        })
      );

      // 动态鉴权：上游 401 → 按 challenge 取 token → 带 token 重放。
      if (response.status === 401) {
        const wwwAuth = response.headers.get("www-authenticate");
        if (wwwAuth && /bearer/i.test(wwwAuth)) {
          const parsed = parseAuthenticate(wwwAuth);
          const { token } = await fetchUpstreamToken(
            parsed,
            request,
            env,
            upstreamHost
          );
          if (token) {
            const authHeaders = new Headers(forwardHeaders);
            authHeaders.set("Authorization", `Bearer ${token}`);
            // 匿名首请求用 cacheTtl:0 且无 cacheEverything，401 不会进缓存，
            // 故重放可复用同一 URL，无 cache-key 碰撞。
            // 服务端凭据仅提升公开仓库额度；客户端自带鉴权的请求仍不缓存。
            response = await fetch(
              new Request(upstreamUrl, {
                method: request.method,
                headers: authHeaders,
                redirect: "follow",
                cf: clientAuthenticated ? { cacheTtl: 0 } : cfCache,
              })
            );
          }
        }
      }

      return finalize(
        response,
        pathname,
        request.method,
        clientAuthenticated
      );
    } catch (error) {
      logError(request, `Fetch error: ${error.message}`);
      return plain(500, "Internal Server Error");
    }
  },
};
