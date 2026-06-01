import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
  DeleteItemCommand,
  ScanCommand,
  QueryCommand
} from "@aws-sdk/client-dynamodb";
import {
  ApiGatewayManagementApiClient,
  PostToConnectionCommand
} from "@aws-sdk/client-apigatewaymanagementapi";
import crypto from "crypto";

const REGION = String(process.env.AWS_REGION || "us-east-2").trim();

const REDIRECTS_TABLE = String(process.env.REDIRECTS_TABLE || "redirects").trim();
const CLICKS_TABLE = String(process.env.CLICKS_TABLE || "clicks").trim();
const WS_CONNECTIONS_TABLE = String(process.env.WS_CONNECTIONS_TABLE || "ws_connections").trim();
const USERS_MIRROR_TABLE = String(process.env.USERS_MIRROR_TABLE || "users_mirror").trim();
const PAYMENTS_MIRROR_TABLE = String(process.env.PAYMENTS_MIRROR_TABLE || "payments_mirror").trim();

const APP_SECRET = String(process.env.APP_SECRET || "").trim();
const PRIMARY_API = normalizeBaseUrl(process.env.PRIMARY_API || "https://api.rattleshortapi.it.com");
const API_BASE = normalizeBaseUrl(
  process.env.API_BASE || "https://suvegwrmzl.execute-api.us-east-2.amazonaws.com/production"
);
const FRONTEND_BASE = normalizeBaseUrl(process.env.FRONTEND_BASE || "https://www.rattleshortit.it.com");
const WS_ENDPOINT = String(
  process.env.WS_ENDPOINT || "https://zzqva6jif7.execute-api.us-east-2.amazonaws.com/production"
).trim();

const ALLOWED_ORIGIN = String(process.env.ALLOWED_ORIGIN || "*").trim();
const INTERNAL_SYNC_KEY = String(process.env.INTERNAL_SYNC_KEY || "").trim();
const CLICK_HISTORY_QUERY_LIMIT = clampInt(process.env.CLICK_HISTORY_QUERY_LIMIT, 1000, 1, 100000);

const DEFAULT_PUBLIC_HOST = normalizeHostname(process.env.DEFAULT_PUBLIC_HOST || API_BASE);
const DEFAULT_LANDING_THEME = "#00ffff";
const MAX_LANDING_HTML_LENGTH = 200000;
const MAX_LANDING_CSS_LENGTH = 100000;
const MAX_LANDING_JS_LENGTH = 100000;
const MAX_META_TITLE_LENGTH = 255;
const MAX_META_DESCRIPTION_LENGTH = 1000;
const MAX_DESCRIPTION_LENGTH = 4000;
const MAX_TITLE_LENGTH = 200;
const MAX_SUBTITLE_LENGTH = 180;
const MAX_FOOTER_LENGTH = 300;
const MAX_IMAGE_LENGTH = 2048;
const MAX_CTA_LABEL_LENGTH = 120;
const MAX_CTA_URL_LENGTH = 2048;
const MAX_DOMAIN_LABEL_LENGTH = 253;

const RESERVED_ROUTES = new Set([
  "/",
  "/health",
  "/debug/echo",
  "/login",
  "/signup",
  "/forgot",
  "/reset",
  "/verify-email",
  "/resend-verify",
  "/magic-request",
  "/magic-approve",
  "/magic-status",
  "/magic-login",
  "/me",
  "/plans",
  "/payment-request",
  "/payments/me",
  "/payment-i-made",
  "/create",
  "/list",
  "/history",
  "/delete",
  "/landing/create",
  "/landing/update",
  "/landing/delete",
  "/domains/me",
  "/domains/add",
  "/domains/verify",
  "/domains/set-primary",
  "/domains/remove",
  "/domains/refresh",
  "/domains/status",
  "/domains/dns-instructions",
  "/support-info",
  "/faq",
  "/about",
  "/legal",
  "/support/my-tickets",
  "/support/contact",
  "/internal/sync-user",
  "/internal/sync-payment",
  "/internal/delete-payment",
  "/admin/users",
  "/admin/payments",
  "/admin/payment-verify",
  "/admin/payment-cancel",
  "/admin/payment-delete",
  "/admin/subscription-pause",
  "/admin/subscription-resume",
  "/admin/create-user",
  "/admin/make-admin",
  "/admin/remove-admin",
  "/admin/ban",
  "/admin/unban",
  "/admin/geo",
  "/admin/verify-user",
  "/admin/email-logs",
  "/admin/audit",
  "/admin/links",
  "/admin/pause",
  "/admin/resume",
  "/admin/support-tickets",
  "/admin/support-ticket-status",
  "/admin/domains",
  "/admin/domain-delete"
]);

const PROXY_EXACT_ROUTES = new Set([
  "/login",
  "/signup",
  "/forgot",
  "/reset",
  "/verify-email",
  "/resend-verify",
  "/magic-request",
  "/magic-approve",
  "/magic-status",
  "/magic-login",
  "/me",
  "/plans",
  "/payment-request",
  "/payments/me",
  "/payment-i-made",
  "/support-info",
  "/faq",
  "/about",
  "/legal",
  "/support/my-tickets",
  "/support/contact",
  "/admin/users",
  "/admin/payments",
  "/admin/payment-verify",
  "/admin/payment-cancel",
  "/admin/payment-delete",
  "/admin/subscription-pause",
  "/admin/subscription-resume",
  "/admin/create-user",
  "/admin/make-admin",
  "/admin/remove-admin",
  "/admin/ban",
  "/admin/unban",
  "/admin/geo",
  "/admin/verify-user",
  "/admin/email-logs",
  "/admin/audit",
  "/admin/support-tickets",
  "/admin/support-ticket-status",
  "/admin/domains",
  "/admin/domain-delete"
]);

const DOMAIN_PROXY_ROUTES = new Set([
  "/domains/me",
  "/domains/add",
  "/domains/verify",
  "/domains/set-primary",
  "/domains/remove",
  "/domains/refresh",
  "/domains/status",
  "/domains/dns-instructions"
]);

const db = new DynamoDBClient({ region: REGION });

const corsHeaders = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "Content-Type,Authorization,x-rattle-fallback,x-internal-key",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
};

function response(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: { ...corsHeaders, ...extraHeaders },
    body: typeof body === "string" ? body : JSON.stringify(body)
  };
}

function json(statusCode, data, extraHeaders = {}) {
  return response(statusCode, data, { "Content-Type": "application/json", ...extraHeaders });
}

function text(statusCode, message, extraHeaders = {}) {
  return response(statusCode, message, { "Content-Type": "text/plain; charset=utf-8", ...extraHeaders });
}

function html(statusCode, markup, extraHeaders = {}) {
  return response(statusCode, markup, { "Content-Type": "text/html; charset=utf-8", ...extraHeaders });
}

function redirect302(location) {
  return {
    statusCode: 302,
    headers: {
      ...corsHeaders,
      Location: location,
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store"
    },
    body: ""
  };
}

const ok = (data) => json(200, data);
const badRequest = (message, extra = {}) => json(400, { message, ...extra });
const unauthorized = (message = "Unauthorized", extra = {}) => json(401, { message, ...extra });
const forbidden = (message = "Forbidden", extra = {}) => json(403, { message, ...extra });
const notFound = (message = "Not found") => json(404, { message });
const conflict = (message = "Resource already exists") => json(409, { message });
const methodNotAllowed = (message = "Method not allowed") => json(405, { message });
function serverError(message = "Internal server error", error = null) {
  console.error(message, error);
  return json(500, { message, error: error?.message || undefined });
}

function getMethod(event) {
  return event?.requestContext?.http?.method || event?.httpMethod || "GET";
}

function getPath(event) {
  const candidates = [
    event?.rawPath,
    event?.requestContext?.http?.path,
    event?.path,
    event?.requestContext?.path
  ].filter(Boolean);

  let raw = candidates[0] || "/";
  raw = String(raw).split("?")[0];
  raw = raw.replace(/^https?:\/\/[^/]+/i, "");
  raw = raw.replace(/^\/(production|prod)(?=\/|$)/i, "") || "/";
  raw = raw.startsWith("/") ? raw : `/${raw}`;
  raw = raw.replace(/\/+/g, "/");
  raw = raw !== "/" ? raw.replace(/\/$/, "") : raw;
  return raw.toLowerCase();
}

function getHeaders(event) {
  return event?.headers || {};
}

function getHeader(event, name) {
  const headers = getHeaders(event);
  return headers[name] || headers[name.toLowerCase()] || headers[name.toUpperCase()] || "";
}

function getQuery(event) {
  return event?.queryStringParameters || {};
}

function getBody(event) {
  if (!event?.body) return {};
  try {
    if (event.isBase64Encoded) {
      const decoded = Buffer.from(event.body, "base64").toString("utf8");
      return decoded ? JSON.parse(decoded) : {};
    }
    return typeof event.body === "string" ? JSON.parse(event.body) : event.body;
  } catch {
    return {};
  }
}

function toNumber(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function clampInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

function normalizeBaseUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const url = new URL(raw);
    return url.toString().replace(/\/+$/, "");
  } catch {
    return raw.replace(/\/+$/, "");
  }
}

function normalizeHostname(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    if (raw.startsWith("http://") || raw.startsWith("https://")) {
      return new URL(raw).hostname.toLowerCase();
    }
    return raw.replace(/^\/+|\/+$/g, "").toLowerCase();
  } catch {
    return raw.replace(/^https?:\/\//i, "").split("/")[0].trim().toLowerCase();
  }
}

function normalizeDomain(value) {
  return normalizeHostname(String(value || "").trim());
}

function normalizeSlug(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeNullableText(value, maxLength = 100000) {
  if (value === undefined || value === null) return null;
  const str = String(value).trim();
  if (!str) return null;
  return str.slice(0, maxLength);
}

function normalizeSafeText(value, maxLength = 255) {
  return String(value || "").trim().slice(0, maxLength);
}

function isValidUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function isValidSlug(slug) {
  return /^[a-z0-9][a-z0-9-_]{2,63}$/.test(String(slug || ""));
}

function isValidDomain(domain) {
  const d = normalizeDomain(domain);
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d) && !d.startsWith(".") && !d.endsWith(".") && d.length <= MAX_DOMAIN_LABEL_LENGTH;
}

function isHexColor(value) {
  return /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.test(String(value || "").trim());
}

function sanitizeThemeColor(value) {
  const theme = String(value || DEFAULT_LANDING_THEME).trim();
  return isHexColor(theme) ? theme : DEFAULT_LANDING_THEME;
}

function now() {
  return Date.now();
}

function randomId(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

function generateSlug() {
  return crypto.randomBytes(4).toString("hex").slice(0, 8).toLowerCase();
}

function normalizePossibleIp(ip) {
  let value = String(ip || "").trim();
  if (!value) return "";
  if (value.includes(",")) value = value.split(",")[0].trim();
  if (value.startsWith("::ffff:")) value = value.replace("::ffff:", "");
  if (value === "::1") value = "127.0.0.1";
  return value;
}

function getIP(event) {
  const headers = getHeaders(event);
  const candidates = [
    headers["cf-connecting-ip"],
    headers["x-real-ip"],
    headers["x-client-ip"],
    headers["x-forwarded-for"],
    event?.requestContext?.http?.sourceIp,
    event?.requestContext?.identity?.sourceIp
  ];
  for (const candidate of candidates) {
    const ip = normalizePossibleIp(candidate);
    if (ip) return ip;
  }
  return "unknown";
}

function getRequestHost(event) {
  const forwardedHost = String(getHeader(event, "x-forwarded-host") || "").trim();
  const hostHeader = String(getHeader(event, "host") || "").trim();
  const raw = forwardedHost || hostHeader || "";
  return normalizeDomain(raw.split(",")[0].split(":")[0]);
}

function isDefaultHost(host) {
  const normalized = normalizeDomain(host);
  return (
    normalized === DEFAULT_PUBLIC_HOST ||
    normalized === normalizeHostname(PRIMARY_API) ||
    normalized === normalizeHostname(API_BASE)
  );
}

function isBot(headers = {}) {
  const ua = String(headers["user-agent"] || headers["User-Agent"] || "").toLowerCase();
  return (
    ua.includes("bot") ||
    ua.includes("crawl") ||
    ua.includes("spider") ||
    ua.includes("curl") ||
    ua.includes("wget") ||
    ua.includes("python") ||
    ua.includes("scrapy") ||
    ua.includes("headless") ||
    ua.includes("selenium") ||
    ua.includes("playwright") ||
    ua.length < 5
  );
}

function isVPN(ip, headers = {}) {
  const ua = String(headers["user-agent"] || headers["User-Agent"] || "").toLowerCase();
  return (
    String(ip).startsWith("10.") ||
    String(ip).startsWith("192.168.") ||
    String(ip).startsWith("127.") ||
    String(ip).startsWith("172.") ||
    ua.includes("vpn") ||
    ua.includes("proxy") ||
    ua.includes("tor")
  );
}

function scoreIP(ip, headers = {}) {
  let score = 0;
  if (ip === "unknown") score += 40;
  if (
    String(ip).startsWith("10.") ||
    String(ip).startsWith("192.168.") ||
    String(ip).startsWith("127.") ||
    String(ip).startsWith("172.")
  ) score += 30;
  if (isVPN(ip, headers)) score += 20;
  if (isBot(headers)) score += 40;
  return Math.min(score, 100);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function parseLandingButtons(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function sanitizeLandingButtons(buttons) {
  const list = Array.isArray(buttons) ? buttons : [];
  return list
    .map((item) => ({
      label: normalizeSafeText(item?.label || "", MAX_CTA_LABEL_LENGTH),
      url: normalizeSafeText(item?.url || "", MAX_CTA_URL_LENGTH)
    }))
    .filter((item) => item.label && isValidUrl(item.url))
    .slice(0, 20);
}

function buildPublicLink(domain, slug) {
  const cleanSlug = normalizeSlug(slug);
  if (domain) return `https://${normalizeDomain(domain)}/${cleanSlug}`;
  return `${API_BASE.replace(/\/+$/, "")}/${cleanSlug}`;
}

function safeJsonStringify(value, fallback = "[]") {
  try {
    return JSON.stringify(value);
  } catch {
    return fallback;
  }
}

function sanitizeLandingPayload(body, existing = null) {
  const resolvedTitle = normalizeSafeText(body.title ?? existing?.landingTitle ?? "", MAX_TITLE_LENGTH);
  const resolvedSubtitle = normalizeSafeText(body.subtitle ?? existing?.landingSubtitle ?? "", MAX_SUBTITLE_LENGTH);
  const resolvedDescription = normalizeSafeText(body.description ?? existing?.landingDescription ?? "", MAX_DESCRIPTION_LENGTH);
  const resolvedImage = normalizeSafeText(body.image ?? existing?.landingImage ?? "", MAX_IMAGE_LENGTH);
  const resolvedTheme = sanitizeThemeColor(body.theme ?? existing?.landingTheme ?? DEFAULT_LANDING_THEME);
  const resolvedButtons = sanitizeLandingButtons(body.buttons ?? existing?.landingButtons ?? []);
  const resolvedCtaLabel = normalizeSafeText(body.ctaLabel ?? existing?.landingCtaLabel ?? "", MAX_CTA_LABEL_LENGTH);
  const resolvedCtaUrl = normalizeSafeText(body.ctaUrl ?? existing?.landingCtaUrl ?? "", MAX_CTA_URL_LENGTH);
  const resolvedFooter = normalizeSafeText(body.footer ?? existing?.landingFooter ?? "", MAX_FOOTER_LENGTH);
  const resolvedLandingHtml = body.landingHtml !== undefined ? normalizeNullableText(body.landingHtml, MAX_LANDING_HTML_LENGTH) : existing?.landingHtml || null;
  const resolvedLandingCss = body.landingCss !== undefined ? normalizeNullableText(body.landingCss, MAX_LANDING_CSS_LENGTH) : existing?.landingCss || null;
  const resolvedLandingJs = body.landingJs !== undefined ? normalizeNullableText(body.landingJs, MAX_LANDING_JS_LENGTH) : existing?.landingJs || null;
  const resolvedMetaTitle = body.metaTitle !== undefined ? normalizeNullableText(body.metaTitle, MAX_META_TITLE_LENGTH) : existing?.metaTitle || null;
  const resolvedMetaDescription = body.metaDescription !== undefined ? normalizeNullableText(body.metaDescription, MAX_META_DESCRIPTION_LENGTH) : existing?.metaDescription || null;
  const resolvedOgTitle = body.ogTitle !== undefined ? normalizeNullableText(body.ogTitle, MAX_META_TITLE_LENGTH) : existing?.ogTitle || null;
  const resolvedOgDescription = body.ogDescription !== undefined ? normalizeNullableText(body.ogDescription, MAX_META_DESCRIPTION_LENGTH) : existing?.ogDescription || null;
  const resolvedOgImage = body.ogImage !== undefined ? normalizeNullableText(body.ogImage, MAX_IMAGE_LENGTH) : existing?.ogImage || null;
  const resolvedCanonicalUrl = body.canonicalUrl !== undefined ? normalizeNullableText(body.canonicalUrl, MAX_CTA_URL_LENGTH) : existing?.canonicalUrl || null;

  return {
    title: resolvedTitle,
    subtitle: resolvedSubtitle,
    description: resolvedDescription,
    image: resolvedImage,
    theme: resolvedTheme,
    buttons: resolvedButtons,
    ctaLabel: resolvedCtaLabel,
    ctaUrl: resolvedCtaUrl,
    footer: resolvedFooter,
    landingHtml: resolvedLandingHtml,
    landingCss: resolvedLandingCss,
    landingJs: resolvedLandingJs,
    metaTitle: resolvedMetaTitle,
    metaDescription: resolvedMetaDescription,
    ogTitle: resolvedOgTitle,
    ogDescription: resolvedOgDescription,
    ogImage: resolvedOgImage,
    canonicalUrl: resolvedCanonicalUrl
  };
}

function renderLandingHtml(link) {
  const customHtml = String(link.landingHtml || "").trim();
  if (customHtml) return customHtml;

  const title = escapeHtml(link.landingTitle || link.slug || "Landing Page");
  const subtitle = escapeHtml(link.landingSubtitle || "");
  const description = escapeHtml(link.landingDescription || "");
  const image = String(link.landingImage || "").trim();
  const theme = sanitizeThemeColor(link.landingTheme || DEFAULT_LANDING_THEME);
  const buttons = Array.isArray(link.landingButtons) ? link.landingButtons : [];
  const ctaLabel = escapeHtml(link.landingCtaLabel || "");
  const ctaUrl = String(link.landingCtaUrl || "").trim();
  const footer = escapeHtml(link.landingFooter || "Powered by Rattle Link");
  const customCss = String(link.landingCss || "").trim();
  const customJs = String(link.landingJs || "").trim();
  const metaTitle = escapeHtml(link.metaTitle || link.ogTitle || link.landingTitle || link.slug || "Landing Page");
  const metaDescription = escapeHtml(link.metaDescription || link.ogDescription || link.landingDescription || "");
  const ogTitle = escapeHtml(link.ogTitle || link.metaTitle || link.landingTitle || link.slug || "Landing Page");
  const ogDescription = escapeHtml(link.ogDescription || link.metaDescription || link.landingDescription || "");
  const ogImage = String(link.ogImage || link.landingImage || "").trim();
  const canonicalUrl = String(link.canonicalUrl || buildPublicLink(link.domain || null, link.slug)).trim();

  const safeButtons = buttons
    .map((btn) => ({ label: escapeHtml(btn.label), url: String(btn.url || "").trim() }))
    .filter((btn) => btn.label && isValidUrl(btn.url));

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${metaTitle}</title>
  <meta name="description" content="${metaDescription}" />
  <meta property="og:title" content="${ogTitle}" />
  <meta property="og:description" content="${ogDescription}" />
  <meta property="og:type" content="website" />
  ${ogImage && isValidUrl(ogImage) ? `<meta property="og:image" content="${escapeHtml(ogImage)}" />` : ""}
  ${canonicalUrl && isValidUrl(canonicalUrl) ? `<link rel="canonical" href="${escapeHtml(canonicalUrl)}" />` : ""}
  <style>
    :root{--theme:${theme};--bg:#020617;--card:#0f172a;--text:#e2e8f0;--muted:#94a3b8}
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;font-family:Inter,Arial,sans-serif;background:radial-gradient(circle at top,#0f172a,#000);color:var(--text);display:flex;align-items:center;justify-content:center;padding:24px}
    .card{width:min(560px,100%);background:rgba(15,23,42,.92);border:1px solid rgba(255,255,255,.08);border-radius:22px;padding:28px;box-shadow:0 0 30px rgba(0,0,0,.35);text-align:center}
    .avatar{width:110px;height:110px;margin:0 auto 18px;border-radius:999px;overflow:hidden;border:3px solid var(--theme);background:#111827;display:flex;align-items:center;justify-content:center}
    .avatar img{width:100%;height:100%;object-fit:cover;display:block}
    .eyebrow{display:inline-block;margin:0 0 12px;padding:6px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.10);color:var(--muted);font-size:12px}
    h1{margin:0 0 10px;color:var(--theme);font-size:30px}
    p.desc{margin:0 0 22px;color:var(--muted);line-height:1.7}
    .links{display:grid;gap:12px}.btn{display:block;padding:14px 16px;border-radius:14px;text-decoration:none;font-weight:700;border:1px solid rgba(255,255,255,.08);background:#111827;color:var(--text)}
    .cta{background:var(--theme);color:#000}.footer{margin-top:20px;color:var(--muted);font-size:12px}
    ${customCss}
  </style>
</head>
<body>
  <div class="card">
    ${image && isValidUrl(image) ? `<div class="avatar"><img src="${escapeHtml(image)}" alt="avatar" /></div>` : ""}
    ${subtitle ? `<div class="eyebrow">${subtitle}</div>` : ""}
    <h1>${title}</h1>
    ${description ? `<p class="desc">${description}</p>` : ""}
    <div class="links">
      ${safeButtons.map((btn) => `<a class="btn" href="${escapeHtml(btn.url)}" target="_blank" rel="noopener noreferrer">${btn.label}</a>`).join("")}
      ${ctaLabel && isValidUrl(ctaUrl) ? `<a class="btn cta" href="${escapeHtml(ctaUrl)}" target="_blank" rel="noopener noreferrer">${ctaLabel}</a>` : ""}
    </div>
    <div class="footer">${footer}</div>
  </div>
  ${customJs ? `<script>${customJs}<\/script>` : ""}
</body>
</html>`;
}

function verifySignedToken(token) {
  try {
    const [base, sig] = String(token || "").split(".");
    if (!base || !sig) return null;
    const expected = crypto.createHmac("sha256", APP_SECRET).update(base).digest("base64url");
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return null;
    if (!crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(base, "base64url").toString("utf8"));
    if (!payload?.sub || !payload?.exp) return null;
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

function getBearerToken(event) {
  const auth = getHeader(event, "authorization");
  if (!auth) return null;
  return auth.startsWith("Bearer ") ? auth.slice(7).trim() : auth.trim();
}

async function getCurrentUser(event) {
  const raw = getBearerToken(event);
  if (!raw) return null;
  const payload = verifySignedToken(raw);
  if (!payload?.sub) return null;
  return {
    username: normalizeEmail(payload.sub),
    role: payload.role || "user",
    tokenType: payload.typ || "core"
  };
}

const ddbString = (value) => ({ S: String(value) });
const ddbNumber = (value) => ({ N: String(value) });
const ddbBool = (value) => ({ BOOL: !!value });
const attrString = (item, key, fallback = "") => item?.[key]?.S ?? fallback;
const attrNumber = (item, key, fallback = 0) => item?.[key]?.N !== undefined ? Number(item[key].N) : fallback;
const attrBool = (item, key, fallback = false) => item?.[key]?.BOOL !== undefined ? item[key].BOOL : fallback;

function buildRedirectKey(slug, domain = null) {
  const cleanSlug = normalizeSlug(slug);
  const cleanDomain = normalizeDomain(domain);
  return cleanDomain ? `${cleanDomain}#${cleanSlug}` : cleanSlug;
}

function splitRedirectKey(key) {
  const raw = String(key || "");
  const index = raw.indexOf("#");
  if (index === -1) return { domain: null, slug: normalizeSlug(raw) };
  return {
    domain: normalizeDomain(raw.slice(0, index)),
    slug: normalizeSlug(raw.slice(index + 1))
  };
}

function marshalRedirectItem(data) {
  const item = {
    slug: ddbString(buildRedirectKey(data.slug, data.domain || null)),
    rawSlug: ddbString(normalizeSlug(data.slug)),
    url: ddbString(data.url),
    clicks: ddbNumber(toNumber(data.clicks, 0)),
    paused: ddbBool(!!data.paused),
    user: ddbString(normalizeEmail(data.user)),
    createdAt: ddbNumber(toNumber(data.createdAt, now())),
    source: ddbString(data.source || "legacy"),
    domain: ddbString(normalizeDomain(data.domain || "")),
    linkType: ddbString(data.linkType || "redirect")
  };

  if (data.expire) item.expire = ddbNumber(data.expire);
  if (data.landingTitle) item.landingTitle = ddbString(data.landingTitle);
  if (data.landingSubtitle) item.landingSubtitle = ddbString(data.landingSubtitle);
  if (data.landingDescription) item.landingDescription = ddbString(data.landingDescription);
  if (data.landingImage) item.landingImage = ddbString(data.landingImage);
  if (data.landingTheme) item.landingTheme = ddbString(data.landingTheme);
  if (data.landingButtons) item.landingButtons = ddbString(safeJsonStringify(data.landingButtons, "[]"));
  if (data.landingCtaLabel) item.landingCtaLabel = ddbString(data.landingCtaLabel);
  if (data.landingCtaUrl) item.landingCtaUrl = ddbString(data.landingCtaUrl);
  if (data.landingFooter) item.landingFooter = ddbString(data.landingFooter);
  if (data.landingHtml) item.landingHtml = ddbString(data.landingHtml);
  if (data.landingCss) item.landingCss = ddbString(data.landingCss);
  if (data.landingJs) item.landingJs = ddbString(data.landingJs);
  if (data.metaTitle) item.metaTitle = ddbString(data.metaTitle);
  if (data.metaDescription) item.metaDescription = ddbString(data.metaDescription);
  if (data.ogTitle) item.ogTitle = ddbString(data.ogTitle);
  if (data.ogDescription) item.ogDescription = ddbString(data.ogDescription);
  if (data.ogImage) item.ogImage = ddbString(data.ogImage);
  if (data.canonicalUrl) item.canonicalUrl = ddbString(data.canonicalUrl);

  return item;
}

function unmarshallRedirectItem(item) {
  if (!item) return null;
  const parsed = splitRedirectKey(attrString(item, "slug"));
  return {
    redirectKey: attrString(item, "slug"),
    slug: attrString(item, "rawSlug", parsed.slug),
    domain: attrString(item, "domain", "") || parsed.domain || null,
    url: attrString(item, "url"),
    clicks: attrNumber(item, "clicks", 0),
    paused: attrBool(item, "paused", false),
    user: normalizeEmail(attrString(item, "user")),
    expire: item?.expire?.N ? Number(item.expire.N) : null,
    createdAt: attrNumber(item, "createdAt", 0),
    source: attrString(item, "source", "legacy"),
    linkType: attrString(item, "linkType", "redirect"),
    landingTitle: attrString(item, "landingTitle", ""),
    landingSubtitle: attrString(item, "landingSubtitle", ""),
    landingDescription: attrString(item, "landingDescription", ""),
    landingImage: attrString(item, "landingImage", ""),
    landingTheme: attrString(item, "landingTheme", ""),
    landingButtons: parseLandingButtons(attrString(item, "landingButtons", "")),
    landingCtaLabel: attrString(item, "landingCtaLabel", ""),
    landingCtaUrl: attrString(item, "landingCtaUrl", ""),
    landingFooter: attrString(item, "landingFooter", ""),
    landingHtml: attrString(item, "landingHtml", ""),
    landingCss: attrString(item, "landingCss", ""),
    landingJs: attrString(item, "landingJs", ""),
    metaTitle: attrString(item, "metaTitle", ""),
    metaDescription: attrString(item, "metaDescription", ""),
    ogTitle: attrString(item, "ogTitle", ""),
    ogDescription: attrString(item, "ogDescription", ""),
    ogImage: attrString(item, "ogImage", ""),
    canonicalUrl: attrString(item, "canonicalUrl", "")
  };
}

async function scanAll(TableName) {
  let items = [];
  let lastKey;
  do {
    const res = await db.send(new ScanCommand({ TableName, ExclusiveStartKey: lastKey }));
    items = items.concat(res.Items || []);
    lastKey = res.LastEvaluatedKey;
  } while (lastKey);
  return items;
}

async function getRedirectBySlugAndDomain(slug, domain = null) {
  const exactKey = buildRedirectKey(slug, domain);
  const direct = await db.send(new GetItemCommand({
    TableName: REDIRECTS_TABLE,
    Key: { slug: ddbString(exactKey) }
  }));
  if (direct.Item) return unmarshallRedirectItem(direct.Item);
  return null;
}

async function getLegacyLinksForUser(username) {
  const items = await scanAll(REDIRECTS_TABLE);
  return items
    .map(unmarshallRedirectItem)
    .filter(Boolean)
    .filter((item) => item.user === normalizeEmail(username))
    .sort((a, b) => b.createdAt - a.createdAt);
}

function sanitizeHeadersForProxy(event, extra = {}) {
  const token = getBearerToken(event);
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  return { ...headers, ...extra };
}

async function readResponseBody(res) {
  const textBody = await res.text();
  try {
    return textBody ? JSON.parse(textBody) : {};
  } catch {
    return textBody || "";
  }
}

async function proxyToPrimary(event, path, method = null, body = undefined, extraHeaders = {}) {
  const finalMethod = method || getMethod(event);
  const url = `${PRIMARY_API}${path}`;
  const res = await fetch(url, {
    method: finalMethod,
    headers: sanitizeHeadersForProxy(event, extraHeaders),
    body: finalMethod === "GET" ? undefined : JSON.stringify(body ?? getBody(event))
  });
  const payload = await readResponseBody(res);
  return response(res.status, payload);
}

async function callPrimaryJson(path, method = "GET", body = null, headers = {}) {
  const res = await fetch(`${PRIMARY_API}${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    body: method === "GET" ? undefined : JSON.stringify(body || {})
  });
  const payload = await readResponseBody(res);
  return { ok: res.ok, status: res.status, data: payload };
}

async function fetchVerifiedDomainForUser(event, domain) {
  const normalizedDomain = normalizeDomain(domain);
  if (!normalizedDomain) return null;

  const domainsRes = await proxyToPrimary(event, "/domains/me", "GET");
  if (domainsRes.statusCode !== 200) return null;

  let parsed;
  try {
    parsed = JSON.parse(domainsRes.body || "{}");
  } catch {
    return null;
  }

  const domains = Array.isArray(parsed?.domains) ? parsed.domains : [];
  return domains.find((d) => normalizeDomain(d.domain) === normalizedDomain && String(d.status || "").toLowerCase() === "verified") || null;
}

function requireInternalKey(event) {
  const key = getHeader(event, "x-internal-key");
  return !!INTERNAL_SYNC_KEY && key === INTERNAL_SYNC_KEY;
}

async function handleInternalSyncUser(event) {
  if (!requireInternalKey(event)) return unauthorized("Invalid internal key");
  const body = getBody(event);
  const username = normalizeEmail(body.username);
  if (!username) return badRequest("Missing username");

  // Your Dynamo table screenshot shows users_mirror partition key is id.
  await db.send(new PutItemCommand({
    TableName: USERS_MIRROR_TABLE,
    Item: {
      id: ddbString(username),
      username: ddbString(username),
      role: ddbString(body.role === "admin" ? "admin" : "user"),
      active: ddbBool(body.active !== false),
      twoFactorEnabled: ddbBool(!!body.twoFactorEnabled),
      twoFactorMethod: ddbString(String(body.twoFactorMethod || "")),
      updatedAt: ddbNumber(now())
    }
  }));

  return ok({ message: "User mirror synced" });
}

async function handleInternalSyncPayment(event) {
  if (!requireInternalKey(event)) return unauthorized("Invalid internal key");
  const body = getBody(event);
  const paymentId = String(body.id || "").trim();
  if (!paymentId) return badRequest("Missing payment id");

  await db.send(new PutItemCommand({
    TableName: PAYMENTS_MIRROR_TABLE,
    Item: {
      id: ddbString(paymentId),
      username: ddbString(normalizeEmail(body.username || "")),
      status: ddbString(String(body.status || "unknown")),
      billingCycle: ddbString(String(body.billingCycle || "")),
      planCode: ddbString(String(body.planCode || "")),
      updatedAt: ddbNumber(now())
    }
  }));

  return ok({ message: "Payment mirror synced" });
}

async function handleInternalDeletePayment(event) {
  if (!requireInternalKey(event)) return unauthorized("Invalid internal key");
  const body = getBody(event);
  const paymentId = String(body.id || "").trim();
  if (!paymentId) return badRequest("Missing payment id");

  await db.send(new DeleteItemCommand({
    TableName: PAYMENTS_MIRROR_TABLE,
    Key: { id: ddbString(paymentId) }
  }));

  return ok({ message: "Payment mirror deleted" });
}

async function requireLegacyCreateAccess(event, username, slug, domain, itemType = "redirect") {
  if (!INTERNAL_SYNC_KEY) {
    return {
      ok: false,
      response: serverError("INTERNAL_SYNC_KEY is not configured")
    };
  }

  const access = await callPrimaryJson(
    "/internal/aws-authorize-create",
    "POST",
    { username, itemType },
    { "x-internal-key": INTERNAL_SYNC_KEY }
  );

  if (!access.ok) {
    return {
      ok: false,
      response: response(
        access.status || 403,
        access.data || { message: "Create access denied" }
      )
    };
  }

  const consume = async () => {
    const consumeRes = await callPrimaryJson(
      "/internal/aws-consume-create",
      "POST",
      {
        username,
        slug,
        domain,
        backend: "legacy",
        itemType
      },
      { "x-internal-key": INTERNAL_SYNC_KEY }
    );

    if (!consumeRes.ok) {
      return {
        ok: false,
        response: response(
          consumeRes.status || 403,
          consumeRes.data || { message: "Create consume failed" }
        )
      };
    }

    return { ok: true, data: consumeRes.data };
  };

  return { ok: true, consume };
}

async function pushRealtimeUpdate(type = "click-update") {
  try {
    const connections = await scanAll(WS_CONNECTIONS_TABLE);
    if (!connections.length) return;

    const ws = new ApiGatewayManagementApiClient({ endpoint: WS_ENDPOINT });
    for (const connection of connections) {
      try {
        await ws.send(new PostToConnectionCommand({
          ConnectionId: attrString(connection, "id"),
          Data: JSON.stringify({ type, time: Date.now() })
        }));
      } catch (error) {
        console.error("WS PUSH ERROR", error);
      }
    }
  } catch (error) {
    console.error("REALTIME ERROR", error);
  }
}

async function handleWebSocket(event) {
  const routeKey = event?.requestContext?.routeKey;
  const connectionId = event?.requestContext?.connectionId;
  if (!connectionId) return { statusCode: 200 };

  try {
    if (routeKey === "$connect") {
      await db.send(new PutItemCommand({
        TableName: WS_CONNECTIONS_TABLE,
        Item: {
          id: ddbString(connectionId),
          connectedAt: ddbNumber(Date.now())
        }
      }));
    }

    if (routeKey === "$disconnect") {
      await db.send(new DeleteItemCommand({
        TableName: WS_CONNECTIONS_TABLE,
        Key: { id: ddbString(connectionId) }
      }));
    }

    if (routeKey === "broadcast") {
      await pushRealtimeUpdate("update");
    }

    return { statusCode: 200 };
  } catch (error) {
    console.error("WS ERROR", error);
    return { statusCode: 500 };
  }
}

function authRequired(path) {
  return (
    path === "/create" ||
    path === "/list" ||
    path === "/history" ||
    path === "/delete" ||
    path === "/me" ||
    path === "/plans" ||
    path === "/payment-request" ||
    path === "/payments/me" ||
    path === "/support/my-tickets" ||
    path.startsWith("/admin") ||
    path.startsWith("/domains") ||
    path.startsWith("/landing")
  );
}

async function routeHttp(event) {
  if (event?.requestContext?.connectionId) {
    return handleWebSocket(event);
  }

  const method = getMethod(event);
  const path = getPath(event);
  const headers = getHeaders(event);
  const body = getBody(event);
  const query = getQuery(event);

  if (method === "OPTIONS") return response(200, "");
  if (!APP_SECRET) return serverError("APP_SECRET is not configured");
  if (!(method === "GET" || method === "POST" || method === "OPTIONS")) return methodNotAllowed();

  if (method === "GET" && path === "/debug/echo") {
    return ok({
      method,
      path,
      rawPath: event?.rawPath || null,
      eventPath: event?.path || null,
      requestContextPath: event?.requestContext?.http?.path || null,
      stage: event?.requestContext?.stage || null,
      query,
      hasAuthorization: !!getBearerToken(event),
      host: getRequestHost(event)
    });
  }

  if (method === "GET" && (path === "/" || path === "/health")) {
    return ok({
      ok: true,
      service: "aws-edge-redirect",
      time: now(),
      region: REGION,
      primaryApi: PRIMARY_API,
      apiBase: API_BASE,
      resolvedPath: path
    });
  }

  if (method === "POST" && path === "/internal/sync-user") return handleInternalSyncUser(event);
  if (method === "POST" && path === "/internal/sync-payment") return handleInternalSyncPayment(event);
  if (method === "POST" && path === "/internal/delete-payment") return handleInternalDeletePayment(event);

  if (PROXY_EXACT_ROUTES.has(path) || DOMAIN_PROXY_ROUTES.has(path)) {
    const suffix = method === "GET" && Object.keys(query || {}).length
      ? `${path}?${new URLSearchParams(query).toString()}`
      : path;
    return proxyToPrimary(event, suffix, method, body);
  }

  const currentUser = await getCurrentUser(event);
  if (authRequired(path) && !currentUser) return unauthorized();

  if (method === "GET" && path === "/admin/links") {
    if (currentUser.role !== "admin") return forbidden("Admin only");

    const links = await scanAll(REDIRECTS_TABLE);
    return ok({
      items: links
        .map(unmarshallRedirectItem)
        .filter(Boolean)
        .sort((a, b) => b.createdAt - a.createdAt)
        .map((item) => ({
          slug: item.slug,
          domain: item.domain || null,
          url: item.url,
          clicks: item.clicks,
          paused: item.paused,
          user: item.user,
          expire: item.expire,
          createdAt: item.createdAt,
          source: item.source || "legacy",
          linkType: item.linkType || "redirect",
          landingTitle: item.landingTitle || "",
          landingSubtitle: item.landingSubtitle || "",
          landingDescription: item.landingDescription || "",
          landingImage: item.landingImage || "",
          landingTheme: item.landingTheme || "",
          landingButtons: item.landingButtons || [],
          landingCtaLabel: item.landingCtaLabel || "",
          landingCtaUrl: item.landingCtaUrl || "",
          landingFooter: item.landingFooter || "",
          landingHtml: item.landingHtml || "",
          landingCss: item.landingCss || "",
          landingJs: item.landingJs || "",
          metaTitle: item.metaTitle || "",
          metaDescription: item.metaDescription || "",
          ogTitle: item.ogTitle || "",
          ogDescription: item.ogDescription || "",
          ogImage: item.ogImage || "",
          canonicalUrl: item.canonicalUrl || "",
          publicLink: buildPublicLink(item.domain || null, item.slug)
        }))
    });
  }

  if (method === "POST" && path === "/admin/pause") {
    if (currentUser.role !== "admin") return forbidden("Admin only");
    const slug = normalizeSlug(body.slug);
    const domain = normalizeDomain(body.domain || "");
    if (!slug) return badRequest("Missing slug");

    const existing = await getRedirectBySlugAndDomain(slug, domain || null);
    if (!existing) return notFound("Link not found");

    await db.send(new UpdateItemCommand({
      TableName: REDIRECTS_TABLE,
      Key: { slug: ddbString(buildRedirectKey(slug, domain || null)) },
      UpdateExpression: "SET paused = :p",
      ExpressionAttributeValues: { ":p": ddbBool(true) }
    }));

    return text(200, "paused");
  }

  if (method === "POST" && path === "/admin/resume") {
    if (currentUser.role !== "admin") return forbidden("Admin only");
    const slug = normalizeSlug(body.slug);
    const domain = normalizeDomain(body.domain || "");
    if (!slug) return badRequest("Missing slug");

    const existing = await getRedirectBySlugAndDomain(slug, domain || null);
    if (!existing) return notFound("Link not found");

    await db.send(new UpdateItemCommand({
      TableName: REDIRECTS_TABLE,
      Key: { slug: ddbString(buildRedirectKey(slug, domain || null)) },
      UpdateExpression: "SET paused = :p",
      ExpressionAttributeValues: { ":p": ddbBool(false) }
    }));

    return text(200, "resumed");
  }

  if (method === "POST" && path === "/create") {
    const url = String(body.url || "").trim();
    const providedSlug = body.slug ? normalizeSlug(body.slug) : "";
    const requestedDomain = normalizeDomain(body.domain || "");
    const expire = body.expire ? Number(body.expire) : null;

    if (!isValidUrl(url)) return badRequest("Invalid URL");
    if (providedSlug && !isValidSlug(providedSlug)) return badRequest("Invalid slug");
    if (expire && (!Number.isFinite(expire) || expire <= now())) return badRequest("Invalid expire timestamp");
    if (requestedDomain && !isValidDomain(requestedDomain)) return badRequest("Invalid custom domain");

    let finalDomain = null;
    if (requestedDomain) {
      const verifiedDomain = await fetchVerifiedDomainForUser(event, requestedDomain);
      if (!verifiedDomain) return badRequest("Custom domain not found or not verified");
      finalDomain = requestedDomain;
    }

    let slug = providedSlug;
    if (!slug) {
      let attempts = 0;
      do {
        slug = generateSlug();
        attempts += 1;
      } while ((await getRedirectBySlugAndDomain(slug, finalDomain)) && attempts < 10);

      if (await getRedirectBySlugAndDomain(slug, finalDomain)) {
        slug = `${generateSlug()}${Math.random().toString(36).slice(2, 4)}`;
      }
    }

    const access = await requireLegacyCreateAccess(event, currentUser.username, slug, finalDomain, "redirect");
    if (!access.ok) return access.response;

    await db.send(new PutItemCommand({
      TableName: REDIRECTS_TABLE,
      Item: marshalRedirectItem({
        slug,
        domain: finalDomain,
        url,
        clicks: 0,
        paused: false,
        user: currentUser.username,
        expire: expire || null,
        createdAt: Date.now(),
        source: "legacy",
        linkType: "redirect"
      }),
      ConditionExpression: "attribute_not_exists(slug)"
    }));

    const consume = await access.consume();
    if (!consume.ok) {
      await db.send(new DeleteItemCommand({
        TableName: REDIRECTS_TABLE,
        Key: { slug: ddbString(buildRedirectKey(slug, finalDomain)) }
      }));
      return consume.response;
    }

    return ok({
      link: buildPublicLink(finalDomain || null, slug),
      slug,
      domain: finalDomain,
      source: "legacy",
      linkType: "redirect",
      access: consume.data
    });
  }

  if (method === "GET" && path === "/list") {
    const items = await getLegacyLinksForUser(currentUser.username);
    return ok({
      items: items.map((item) => ({
        slug: item.slug,
        domain: item.domain || null,
        url: item.url,
        clicks: item.clicks,
        paused: item.paused,
        user: item.user,
        expire: item.expire,
        createdAt: item.createdAt,
        source: item.source || "legacy",
        linkType: item.linkType || "redirect",
        landingTitle: item.landingTitle || "",
        landingSubtitle: item.landingSubtitle || "",
        landingDescription: item.landingDescription || "",
        landingImage: item.landingImage || "",
        landingTheme: item.landingTheme || "",
        landingButtons: item.landingButtons || [],
        landingCtaLabel: item.landingCtaLabel || "",
        landingCtaUrl: item.landingCtaUrl || "",
        landingFooter: item.landingFooter || "",
        landingHtml: item.landingHtml || "",
        landingCss: item.landingCss || "",
        landingJs: item.landingJs || "",
        metaTitle: item.metaTitle || "",
        metaDescription: item.metaDescription || "",
        ogTitle: item.ogTitle || "",
        ogDescription: item.ogDescription || "",
        ogImage: item.ogImage || "",
        canonicalUrl: item.canonicalUrl || "",
        publicLink: buildPublicLink(item.domain || null, item.slug)
      }))
    });
  }

  if (method === "GET" && path === "/history") {
    const slug = normalizeSlug(query.slug);
    const domain = normalizeDomain(query.domain || "");
    if (!slug) return badRequest("Missing slug");

    const link = await getRedirectBySlugAndDomain(slug, domain || null);
    if (!link) return notFound("Link not found");
    if (link.user !== currentUser.username && currentUser.role !== "admin") return forbidden("Forbidden");

    const allItems = await scanAll(CLICKS_TABLE);
    const history = allItems
      .filter((i) => attrString(i, "slug").toLowerCase() === slug)
      .filter((i) => normalizeDomain(attrString(i, "domain", "")) === normalizeDomain(domain || ""))
      .map((i) => ({
        id: attrString(i, "id"),
        slug: attrString(i, "slug"),
        domain: attrString(i, "domain", "") || null,
        time: attrNumber(i, "time", Date.now()),
        ip: attrString(i, "ip", "unknown"),
        vpn: attrBool(i, "vpn", false),
        bot: attrBool(i, "bot", false),
        risk: attrNumber(i, "risk", 0),
        ua: attrString(i, "ua", "unknown")
      }))
      .sort((a, b) => b.time - a.time)
      .slice(0, CLICK_HISTORY_QUERY_LIMIT);

    return ok({ history });
  }

  if (method === "POST" && path === "/delete") {
    const slug = normalizeSlug(body.slug);
    const domain = normalizeDomain(body.domain || "");
    if (!slug) return badRequest("Missing slug");

    const link = await getRedirectBySlugAndDomain(slug, domain || null);
    if (!link) return notFound("Link not found");
    if (link.user !== currentUser.username && currentUser.role !== "admin") return forbidden("Forbidden");

    await db.send(new DeleteItemCommand({
      TableName: REDIRECTS_TABLE,
      Key: { slug: ddbString(buildRedirectKey(slug, domain || null)) }
    }));

    return text(200, "deleted");
  }

  if (method === "POST" && path === "/landing/create") {
    const requestedDomain = normalizeDomain(body.domain || "");
    const slug = normalizeSlug(body.slug || generateSlug());

    if (!isValidSlug(slug)) return badRequest("Invalid slug");
    if (requestedDomain && !isValidDomain(requestedDomain)) return badRequest("Invalid custom domain");

    let finalDomain = null;
    if (requestedDomain) {
      const verifiedDomain = await fetchVerifiedDomainForUser(event, requestedDomain);
      if (!verifiedDomain) return badRequest("Custom domain not found or not verified");
      finalDomain = requestedDomain;
    }

    const sanitized = sanitizeLandingPayload(body);
    if (!sanitized.title && !sanitized.landingHtml) return badRequest("Landing title required");
    if (sanitized.image && !isValidUrl(sanitized.image)) return badRequest("Invalid landing image URL");
    if (sanitized.ctaUrl && !isValidUrl(sanitized.ctaUrl)) return badRequest("Invalid CTA URL");
    if (sanitized.ogImage && !isValidUrl(sanitized.ogImage)) return badRequest("Invalid OG image URL");
    if (sanitized.canonicalUrl && !isValidUrl(sanitized.canonicalUrl)) return badRequest("Invalid canonical URL");

    const existing = await getRedirectBySlugAndDomain(slug, finalDomain);
    if (existing) return conflict("Resource already exists");

    const access = await requireLegacyCreateAccess(event, currentUser.username, slug, finalDomain, "landing");
    if (!access.ok) return access.response;

    await db.send(new PutItemCommand({
      TableName: REDIRECTS_TABLE,
      Item: marshalRedirectItem({
        slug,
        domain: finalDomain,
        url: sanitized.ctaUrl || FRONTEND_BASE,
        clicks: 0,
        paused: false,
        user: currentUser.username,
        expire: null,
        createdAt: now(),
        source: "legacy",
        linkType: "landing",
        landingTitle: sanitized.title || slug,
        landingSubtitle: sanitized.subtitle || null,
        landingDescription: sanitized.description || null,
        landingImage: sanitized.image || null,
        landingTheme: sanitized.theme,
        landingButtons: sanitized.buttons,
        landingCtaLabel: sanitized.ctaLabel || null,
        landingCtaUrl: sanitized.ctaUrl || null,
        landingFooter: sanitized.footer || null,
        landingHtml: sanitized.landingHtml,
        landingCss: sanitized.landingCss,
        landingJs: sanitized.landingJs,
        metaTitle: sanitized.metaTitle,
        metaDescription: sanitized.metaDescription,
        ogTitle: sanitized.ogTitle,
        ogDescription: sanitized.ogDescription,
        ogImage: sanitized.ogImage,
        canonicalUrl: sanitized.canonicalUrl
      }),
      ConditionExpression: "attribute_not_exists(slug)"
    }));

    const consume = await access.consume();
    if (!consume.ok) {
      await db.send(new DeleteItemCommand({
        TableName: REDIRECTS_TABLE,
        Key: { slug: ddbString(buildRedirectKey(slug, finalDomain)) }
      }));
      return consume.response;
    }

    return ok({
      message: "Landing page created",
      slug,
      domain: finalDomain,
      linkType: "landing",
      link: buildPublicLink(finalDomain || null, slug)
    });
  }

  if (method === "POST" && path === "/landing/update") {
    const slug = normalizeSlug(body.slug);
    const domain = normalizeDomain(body.domain || "");
    if (!slug) return badRequest("Missing slug");

    const item = await getRedirectBySlugAndDomain(slug, domain || null);
    if (!item) return notFound("Landing page not found");
    if (item.user !== currentUser.username && currentUser.role !== "admin") return forbidden("Forbidden");
    if (String(item.linkType || "redirect") !== "landing") return badRequest("This is not a landing page");

    const sanitized = sanitizeLandingPayload(body, item);
    if (!sanitized.title && !sanitized.landingHtml) return badRequest("Landing title required");
    if (sanitized.image && !isValidUrl(sanitized.image)) return badRequest("Invalid landing image URL");
    if (sanitized.ctaUrl && !isValidUrl(sanitized.ctaUrl)) return badRequest("Invalid CTA URL");
    if (sanitized.ogImage && !isValidUrl(sanitized.ogImage)) return badRequest("Invalid OG image URL");
    if (sanitized.canonicalUrl && !isValidUrl(sanitized.canonicalUrl)) return badRequest("Invalid canonical URL");

    await db.send(new PutItemCommand({
      TableName: REDIRECTS_TABLE,
      Item: marshalRedirectItem({
        slug,
        domain: domain || null,
        url: sanitized.ctaUrl || item.url || FRONTEND_BASE,
        clicks: item.clicks,
        paused: item.paused,
        user: item.user,
        expire: item.expire,
        createdAt: item.createdAt,
        source: item.source || "legacy",
        linkType: "landing",
        landingTitle: sanitized.title || slug,
        landingSubtitle: sanitized.subtitle || null,
        landingDescription: sanitized.description || null,
        landingImage: sanitized.image || null,
        landingTheme: sanitized.theme,
        landingButtons: sanitized.buttons,
        landingCtaLabel: sanitized.ctaLabel || null,
        landingCtaUrl: sanitized.ctaUrl || null,
        landingFooter: sanitized.footer || null,
        landingHtml: sanitized.landingHtml,
        landingCss: sanitized.landingCss,
        landingJs: sanitized.landingJs,
        metaTitle: sanitized.metaTitle,
        metaDescription: sanitized.metaDescription,
        ogTitle: sanitized.ogTitle,
        ogDescription: sanitized.ogDescription,
        ogImage: sanitized.ogImage,
        canonicalUrl: sanitized.canonicalUrl
      })
    }));

    return ok({ message: "Landing page updated" });
  }

  if (method === "POST" && path === "/landing/delete") {
    const slug = normalizeSlug(body.slug);
    const domain = normalizeDomain(body.domain || "");
    if (!slug) return badRequest("Missing slug");

    const item = await getRedirectBySlugAndDomain(slug, domain || null);
    if (!item) return notFound("Landing page not found");
    if (item.user !== currentUser.username && currentUser.role !== "admin") return forbidden("Forbidden");
    if (String(item.linkType || "redirect") !== "landing") return badRequest("This is not a landing page");

    await db.send(new DeleteItemCommand({
      TableName: REDIRECTS_TABLE,
      Key: { slug: ddbString(buildRedirectKey(slug, domain || null)) }
    }));

    return ok({ message: "Landing page deleted" });
  }

  if (method === "GET" && path.startsWith("/landing/")) {
    const slug = normalizeSlug(path.replace("/landing/", ""));
    const domain = normalizeDomain(query.domain || "");

    const item = await getRedirectBySlugAndDomain(slug, domain || null);
    if (!item) return notFound("Landing page not found");
    if (item.user !== currentUser.username && currentUser.role !== "admin") return forbidden("Forbidden");

    return ok({
      slug: item.slug,
      domain: item.domain || null,
      linkType: item.linkType || "landing",
      title: item.landingTitle || "",
      subtitle: item.landingSubtitle || "",
      description: item.landingDescription || "",
      image: item.landingImage || "",
      theme: item.landingTheme || DEFAULT_LANDING_THEME,
      buttons: item.landingButtons || [],
      ctaLabel: item.landingCtaLabel || "",
      ctaUrl: item.landingCtaUrl || "",
      footer: item.landingFooter || "",
      landingHtml: item.landingHtml || "",
      landingCss: item.landingCss || "",
      landingJs: item.landingJs || "",
      metaTitle: item.metaTitle || "",
      metaDescription: item.metaDescription || "",
      ogTitle: item.ogTitle || "",
      ogDescription: item.ogDescription || "",
      ogImage: item.ogImage || "",
      canonicalUrl: item.canonicalUrl || ""
    });
  }

  if (method === "GET" && !RESERVED_ROUTES.has(path) && !path.startsWith("/admin")) {
    const slug = normalizeSlug(path.split("/").filter(Boolean).pop());
    if (!slug) return badRequest("Invalid slug");

    const host = getRequestHost(event);
    const domainToResolve = isDefaultHost(host) ? null : host;

    const item = await getRedirectBySlugAndDomain(slug, domainToResolve);
    if (!item) return notFound("Link not found");
    if (item.paused) return forbidden("Link is paused");
    if (item.expire && Date.now() > item.expire) return json(410, { message: "Link expired" });

    const ip = getIP(event);
    const risk = scoreIP(ip, headers);
    const ua = headers["user-agent"] || headers["User-Agent"] || "unknown";

    await db.send(new UpdateItemCommand({
      TableName: REDIRECTS_TABLE,
      Key: { slug: ddbString(buildRedirectKey(slug, domainToResolve)) },
      UpdateExpression: "SET clicks = if_not_exists(clicks, :z) + :i",
      ExpressionAttributeValues: {
        ":i": ddbNumber(1),
        ":z": ddbNumber(0)
      }
    }));

    await db.send(new PutItemCommand({
      TableName: CLICKS_TABLE,
      Item: {
        id: ddbString(`${slug}#${normalizeDomain(domainToResolve || "")}#${Date.now()}#${randomId(4)}`),
        slug: ddbString(slug),
        domain: ddbString(normalizeDomain(domainToResolve || "")),
        time: ddbNumber(Date.now()),
        ip: ddbString(ip),
        vpn: ddbBool(isVPN(ip, headers)),
        bot: ddbBool(isBot(headers)),
        risk: ddbNumber(risk),
        ua: ddbString(ua)
      }
    }));

    await pushRealtimeUpdate("click-update");

    if (String(item.linkType || "redirect") === "landing") {
      return html(200, renderLandingHtml(item), { "Cache-Control": "no-store" });
    }

    return redirect302(item.url);
  }

  return notFound(`Route not found: ${method} ${path}`);
}

export const handler = async (event) => {
  try {
    return await routeHttp(event);
  } catch (error) {
    console.error("UNHANDLED ERROR", error);
    if (error?.name === "ConditionalCheckFailedException") return conflict("Resource already exists");
    if (error?.name === "ProvisionedThroughputExceededException") return serverError("DynamoDB throughput exceeded", error);
    if (error?.name === "ThrottlingException") return serverError("AWS throttling", error);
    return serverError("Internal server error", error);
  }
};
