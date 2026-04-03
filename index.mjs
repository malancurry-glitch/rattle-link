import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
  DeleteItemCommand,
  ScanCommand
} from "@aws-sdk/client-dynamodb";
import {
  ApiGatewayManagementApiClient,
  PostToConnectionCommand
} from "@aws-sdk/client-apigatewaymanagementapi";
import crypto from "crypto";

// ================= CONFIG =================
const REGION = process.env.AWS_REGION || "us-east-2";

const REDIRECTS_TABLE = process.env.REDIRECTS_TABLE || "redirects";
const CLICKS_TABLE = process.env.CLICKS_TABLE || "clicks";
const WS_CONNECTIONS_TABLE = process.env.WS_CONNECTIONS_TABLE || "ws_connections";

const APP_SECRET = process.env.APP_SECRET || "6360dffbeee180ce660717dc8401497b5985e8abf13c6d056435196bee8dd14b4560f499ed022484285d4e84d9e18409b9937a4f4424e6b08c7e1e8a457c4656";
const PRIMARY_API = (process.env.PRIMARY_API || "https://rattleshortapi.it.com").replace(/\/+$/, "");
const API_BASE = (process.env.API_BASE || "https://suvegwrmzl.execute-api.us-east-2.amazonaws.com/production").replace(/\/+$/, "");
const FRONTEND_BASE = (process.env.FRONTEND_BASE || "https://rattle-link.vercel.app").replace(/\/+$/, "");
const WS_ENDPOINT = process.env.WS_ENDPOINT || "https://zzqva6jif7.execute-api.us-east-2.amazonaws.com/production";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
const INTERNAL_SYNC_KEY = process.env.INTERNAL_SYNC_KEY || "6360dffbeee180ce660717dc8401497b5985e8abf13c6d056435196bee8dd14b4560f499ed022484285d4e84d9e18409b9937a4f4424e6b08c7e1e8a457c4656";
const CLICK_HISTORY_QUERY_LIMIT = Number(process.env.CLICK_HISTORY_QUERY_LIMIT || 1000);

// ================= CLIENTS =================
const db = new DynamoDBClient({ region: REGION });

// ================= CORS =================
const corsHeaders = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "Content-Type,Authorization,x-rattle-fallback,x-internal-key",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
};

// ================= RESPONSE HELPERS =================
function response(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      ...corsHeaders,
      ...extraHeaders
    },
    body: typeof body === "string" ? body : JSON.stringify(body)
  };
}

function json(statusCode, data, extraHeaders = {}) {
  return response(statusCode, data, {
    "Content-Type": "application/json",
    ...extraHeaders
  });
}

function text(statusCode, message, extraHeaders = {}) {
  return response(statusCode, message, {
    "Content-Type": "text/plain; charset=utf-8",
    ...extraHeaders
  });
}

function ok(data) {
  return json(200, data);
}

function badRequest(message, extra = {}) {
  return json(400, { message, ...extra });
}

function unauthorized(message = "Unauthorized", extra = {}) {
  return json(401, { message, ...extra });
}

function forbidden(message = "Forbidden", extra = {}) {
  return json(403, { message, ...extra });
}

function notFound(message = "Not found") {
  return json(404, { message });
}

function conflict(message = "Resource already exists") {
  return json(409, { message });
}

function serverError(message = "Internal server error", error = null) {
  console.error(message, error);
  return json(500, {
    message,
    error: error?.message || undefined
  });
}

// ================= EVENT HELPERS =================
function getMethod(event) {
  return event?.requestContext?.http?.method || event?.httpMethod || "GET";
}

function getPath(event) {
  const raw = event?.requestContext?.http?.path || event?.path || "/";
  return (raw.replace(/^\/production/, "") || "/").toLowerCase();
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
    return typeof event.body === "string" ? JSON.parse(event.body) : event.body;
  } catch {
    return {};
  }
}

// ================= GENERAL HELPERS =================
function normalizeSlug(value) {
  return String(value || "").trim().toLowerCase();
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

function now() {
  return Date.now();
}

function randomId(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

function generateSlug() {
  return Math.random().toString(36).slice(2, 8).toLowerCase();
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
    if (!ip) continue;
    return ip;
  }

  return "unknown";
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
  if (String(ip).startsWith("10.") || String(ip).startsWith("192.168.") || String(ip).startsWith("127.") || String(ip).startsWith("172.")) score += 30;
  if (isVPN(ip, headers)) score += 20;
  if (isBot(headers)) score += 40;
  return Math.min(score, 100);
}

// ================= TOKEN HELPERS =================
function verifySignedToken(token) {
  try {
    const [base, sig] = String(token || "").split(".");
    if (!base || !sig) return null;

    const expected = crypto
      .createHmac("sha256", APP_SECRET)
      .update(base)
      .digest("base64url");

    if (sig !== expected) return null;

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
    username: payload.sub,
    role: payload.role || "user",
    tokenType: payload.typ || "core"
  };
}

// ================= DYNAMO HELPERS =================
function ddbString(value) {
  return { S: String(value) };
}

function ddbNumber(value) {
  return { N: String(value) };
}

function ddbBool(value) {
  return { BOOL: !!value };
}

function attrString(item, key, fallback = "") {
  return item?.[key]?.S ?? fallback;
}

function attrNumber(item, key, fallback = 0) {
  return item?.[key]?.N !== undefined ? Number(item[key].N) : fallback;
}

function attrBool(item, key, fallback = false) {
  return item?.[key]?.BOOL !== undefined ? item[key].BOOL : fallback;
}

async function scanAll(TableName) {
  let items = [];
  let lastKey;

  do {
    const res = await db.send(
      new ScanCommand({
        TableName,
        ExclusiveStartKey: lastKey
      })
    );
    items = items.concat(res.Items || []);
    lastKey = res.LastEvaluatedKey;
  } while (lastKey);

  return items;
}

async function getRedirect(slug) {
  const res = await db.send(
    new GetItemCommand({
      TableName: REDIRECTS_TABLE,
      Key: { slug: ddbString(slug) }
    })
  );
  return res.Item || null;
}

// ================= BACKEND2 PROXY HELPERS =================
function sanitizeHeadersForProxy(event, extra = {}) {
  const token = getBearerToken(event);
  const headers = {
    "Content-Type": "application/json"
  };

  if (token) headers.Authorization = `Bearer ${token}`;

  return {
    ...headers,
    ...extra
  };
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
    headers: {
      "Content-Type": "application/json",
      ...headers
    },
    body: method === "GET" ? undefined : JSON.stringify(body || {})
  });

  const payload = await readResponseBody(res);
  return {
    ok: res.ok,
    status: res.status,
    data: payload
  };
}

// ================= INTERNAL SYNC ROUTES =================
function requireInternalKey(event) {
  const key = getHeader(event, "x-internal-key");
  return !!INTERNAL_SYNC_KEY && key === INTERNAL_SYNC_KEY;
}

async function handleInternalSyncUser(event) {
  if (!requireInternalKey(event)) return unauthorized("Invalid internal key");

  const body = getBody(event);
  const username = String(body.username || "").trim().toLowerCase();
  if (!username) return badRequest("Missing username");

  const role = body.role === "admin" ? "admin" : "user";
  const active = body.active !== false;

  await db.send(
    new PutItemCommand({
      TableName: "users_mirror",
      Item: {
        username: ddbString(username),
        role: ddbString(role),
        active: ddbBool(active),
        updatedAt: ddbNumber(now())
      }
    })
  );

  return ok({ message: "User mirror synced" });
}

async function handleInternalSyncPayment(event) {
  if (!requireInternalKey(event)) return unauthorized("Invalid internal key");

  const body = getBody(event);
  const paymentId = String(body.id || "").trim();
  if (!paymentId) return badRequest("Missing payment id");

  await db.send(
    new PutItemCommand({
      TableName: "payments_mirror",
      Item: {
        id: ddbString(paymentId),
        username: ddbString(String(body.username || "")),
        status: ddbString(String(body.status || "unknown")),
        billingCycle: ddbString(String(body.billingCycle || "")),
        updatedAt: ddbNumber(now())
      }
    })
  );

  return ok({ message: "Payment mirror synced" });
}

// ================= REALTIME =================
async function pushRealtimeUpdate(type = "click-update") {
  try {
    const connections = await scanAll(WS_CONNECTIONS_TABLE);
    if (!connections.length) return;

    const ws = new ApiGatewayManagementApiClient({ endpoint: WS_ENDPOINT });

    for (const connection of connections) {
      try {
        await ws.send(
          new PostToConnectionCommand({
            ConnectionId: attrString(connection, "id"),
            Data: JSON.stringify({ type, time: Date.now() })
          })
        );
      } catch (error) {
        console.error("WS PUSH ERROR", error);
      }
    }
  } catch (error) {
    console.error("REALTIME ERROR", error);
  }
}

// ================= WEBSOCKET =================
async function handleWebSocket(event) {
  const routeKey = event?.requestContext?.routeKey;
  const connectionId = event?.requestContext?.connectionId;

  if (!connectionId) return { statusCode: 200 };

  try {
    if (routeKey === "$connect") {
      await db.send(
        new PutItemCommand({
          TableName: WS_CONNECTIONS_TABLE,
          Item: {
            id: ddbString(connectionId),
            connectedAt: ddbNumber(Date.now())
          }
        })
      );
    }

    if (routeKey === "$disconnect") {
      await db.send(
        new DeleteItemCommand({
          TableName: WS_CONNECTIONS_TABLE,
          Key: { id: ddbString(connectionId) }
        })
      );
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

// ================= AUTH CHECK =================
function authRequired(path) {
  return (
    path === "/create" ||
    path === "/list" ||
    path === "/history" ||
    path === "/delete" ||
    path === "/me" ||
    path === "/plans" ||
    path.startsWith("/admin") ||
    path === "/payment-request" ||
    path === "/payments/me"
  );
}

// ================= MAIN ROUTER =================
async function routeHttp(event) {
  if (event?.requestContext?.connectionId) {
    return handleWebSocket(event);
  }

  const method = getMethod(event);
  const path = getPath(event);
  const headers = getHeaders(event);
  const body = getBody(event);
  const query = getQuery(event);

  if (method === "OPTIONS") {
    return response(200, "");
  }

  if (!APP_SECRET) {
    return serverError("APP_SECRET is not configured");
  }

  // -------- health
  if (method === "GET" && (path === "/" || path === "/health")) {
    return ok({
      ok: true,
      service: "aws-edge-redirect",
      time: now(),
      region: REGION
    });
  }

  // -------- internal sync
  if (method === "POST" && path === "/internal/sync-user") {
    return handleInternalSyncUser(event);
  }

  if (method === "POST" && path === "/internal/sync-payment") {
    return handleInternalSyncPayment(event);
  }

  // -------- proxy routes to Backend2
  const proxyExactRoutes = new Set([
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
    "/admin/users",
    "/admin/payments",
    "/admin/payment-verify",
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
    "/admin/audit"
  ]);

  if (proxyExactRoutes.has(path)) {
    const suffix = method === "GET" && Object.keys(query || {}).length
      ? `${path}?${new URLSearchParams(query).toString()}`
      : path;
    return proxyToPrimary(event, suffix, method, body);
  }

  const currentUser = await getCurrentUser(event);
  if (authRequired(path) && !currentUser) {
    return unauthorized();
  }

  // -------- local admin links route
  if (method === "GET" && path === "/admin/links") {
    if (currentUser.role !== "admin") return forbidden("Admin only");

    const links = await scanAll(REDIRECTS_TABLE);
    return ok({
      items: links.map((item) => ({
        slug: attrString(item, "slug"),
        url: attrString(item, "url"),
        clicks: attrNumber(item, "clicks"),
        paused: attrBool(item, "paused", false),
        user: attrString(item, "user"),
        expire: item?.expire?.N ? Number(item.expire.N) : null,
        createdAt: attrNumber(item, "createdAt", 0),
        source: "legacy"
      }))
    });
  }

  if (method === "POST" && path === "/admin/pause") {
    if (currentUser.role !== "admin") return forbidden("Admin only");

    const slug = normalizeSlug(body.slug);
    if (!slug) return badRequest("Missing slug");

    await db.send(
      new UpdateItemCommand({
        TableName: REDIRECTS_TABLE,
        Key: { slug: ddbString(slug) },
        UpdateExpression: "SET paused = :p",
        ExpressionAttributeValues: { ":p": ddbBool(true) }
      })
    );

    return text(200, "paused");
  }

  if (method === "POST" && path === "/admin/resume") {
    if (currentUser.role !== "admin") return forbidden("Admin only");

    const slug = normalizeSlug(body.slug);
    if (!slug) return badRequest("Missing slug");

    await db.send(
      new UpdateItemCommand({
        TableName: REDIRECTS_TABLE,
        Key: { slug: ddbString(slug) },
        UpdateExpression: "SET paused = :p",
        ExpressionAttributeValues: { ":p": ddbBool(false) }
      })
    );

    return text(200, "resumed");
  }

  // -------- local create/list/history/delete
  if (method === "POST" && path === "/create") {
    // Backend2 is canonical for who can create.
    const access = await callPrimaryJson("/internal/aws-authorize-create", "POST", {
      username: currentUser.username
    }, {
      Authorization: `Bearer ${getBearerToken(event)}`
    });

    if (!access.ok) {
      return response(access.status, access.data);
    }

    const url = String(body.url || "").trim();
    const providedSlug = body.slug ? normalizeSlug(body.slug) : "";
    const expire = body.expire ? Number(body.expire) : null;

    if (!isValidUrl(url)) return badRequest("Invalid URL");
    if (providedSlug && !isValidSlug(providedSlug)) return badRequest("Invalid slug");

    let slug = providedSlug;
    if (!slug) {
      let attempts = 0;
      do {
        slug = generateSlug();
        attempts += 1;
      } while ((await getRedirect(slug)) && attempts < 10);

      if (await getRedirect(slug)) {
        slug = `${generateSlug()}${Math.random().toString(36).slice(2, 4)}`;
      }
    }

    await db.send(
      new PutItemCommand({
        TableName: REDIRECTS_TABLE,
        Item: {
          slug: ddbString(slug),
          url: ddbString(url),
          clicks: ddbNumber(0),
          paused: ddbBool(false),
          user: ddbString(currentUser.username),
          ...(expire ? { expire: ddbNumber(expire) } : {}),
          createdAt: ddbNumber(Date.now()),
          source: ddbString("legacy")
        },
        ConditionExpression: "attribute_not_exists(slug)"
      })
    );

    const consume = await callPrimaryJson("/internal/aws-consume-create", "POST", {
      username: currentUser.username,
      slug,
      backend: "legacy"
    }, {
      Authorization: `Bearer ${getBearerToken(event)}`
    });

    if (!consume.ok) {
      // rollback if Backend2 refuses consume
      await db.send(
        new DeleteItemCommand({
          TableName: REDIRECTS_TABLE,
          Key: { slug: ddbString(slug) }
        })
      );
      return response(consume.status, consume.data);
    }

    return ok({
      link: `${API_BASE}/${slug}`,
      slug,
      source: "legacy",
      access: consume.data
    });
  }

  if (method === "GET" && path === "/list") {
    const items = await scanAll(REDIRECTS_TABLE);

    return ok({
      items: items
        .filter((item) => attrString(item, "user") === currentUser.username)
        .map((item) => ({
          slug: attrString(item, "slug"),
          url: attrString(item, "url"),
          clicks: attrNumber(item, "clicks"),
          paused: attrBool(item, "paused"),
          user: attrString(item, "user"),
          expire: item?.expire?.N ? Number(item.expire.N) : null,
          createdAt: attrNumber(item, "createdAt", 0),
          source: "legacy"
        }))
    });
  }

  if (method === "GET" && path === "/history") {
    const slug = normalizeSlug(query.slug);
    if (!slug) return badRequest("Missing slug");

    const link = await getRedirect(slug);
    if (!link) return notFound("Link not found");

    const owner = attrString(link, "user");
    if (owner !== currentUser.username && currentUser.role !== "admin") {
      return forbidden("Forbidden");
    }

    const allItems = await scanAll(CLICKS_TABLE);

    const history = allItems
      .filter((i) => attrString(i, "slug").toLowerCase() === slug)
      .map((i) => ({
        id: attrString(i, "id"),
        slug: attrString(i, "slug"),
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
    if (!slug) return badRequest("Missing slug");

    const link = await getRedirect(slug);
    if (!link) return notFound("Link not found");

    const owner = attrString(link, "user");
    if (owner !== currentUser.username && currentUser.role !== "admin") {
      return forbidden("Forbidden");
    }

    await db.send(
      new DeleteItemCommand({
        TableName: REDIRECTS_TABLE,
        Key: { slug: ddbString(slug) }
      })
    );

    return text(200, "deleted");
  }

  // -------- public redirect
  if (method === "GET") {
    const reservedRoutes = new Set([
      "/",
      "/health",
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
      "/create",
      "/list",
      "/history",
      "/delete",
      "/internal/sync-user",
      "/internal/sync-payment",
      "/admin/users",
      "/admin/payments",
      "/admin/payment-verify",
      "/admin/subscription-pause",
      "/admin/subscription-resume",
      "/admin/links",
      "/admin/create-user",
      "/admin/make-admin",
      "/admin/remove-admin",
      "/admin/ban",
      "/admin/unban",
      "/admin/geo",
      "/admin/verify-user",
      "/admin/email-logs",
      "/admin/audit",
      "/admin/pause",
      "/admin/resume"
    ]);

    if (!reservedRoutes.has(path) && !path.startsWith("/admin")) {
      const slug = normalizeSlug(path.split("/").filter(Boolean).pop());
      if (!slug) return badRequest("Invalid slug");

      const item = await getRedirect(slug);
      if (!item) return notFound("Link not found");
      if (attrBool(item, "paused")) return forbidden("Link is paused");

      if (item?.expire?.N) {
        const expireTime = Number(item.expire.N);
        if (Date.now() > expireTime) {
          return json(410, { message: "Link expired" });
        }
      }

      const ip = getIP(event);
      const url = attrString(item, "url");

      await db.send(
        new UpdateItemCommand({
          TableName: REDIRECTS_TABLE,
          Key: { slug: ddbString(slug) },
          UpdateExpression: "SET clicks = if_not_exists(clicks, :z) + :i",
          ExpressionAttributeValues: {
            ":i": ddbNumber(1),
            ":z": ddbNumber(0)
          }
        })
      );

      await db.send(
        new PutItemCommand({
          TableName: CLICKS_TABLE,
          Item: {
            id: ddbString(`${slug}#${Date.now()}#${randomId(4)}`),
            slug: ddbString(slug),
            time: ddbNumber(Date.now()),
            ip: ddbString(ip),
            vpn: ddbBool(isVPN(ip, headers)),
            bot: ddbBool(isBot(headers)),
            risk: ddbNumber(scoreIP(ip, headers)),
            ua: ddbString(headers["user-agent"] || headers["User-Agent"] || "unknown")
          }
        })
      );

      await pushRealtimeUpdate("click-update");

      return {
        statusCode: 302,
        headers: {
          ...corsHeaders,
          Location: url,
          "Content-Type": "text/plain; charset=utf-8"
        },
        body: ""
      };
    }
  }

  return notFound("Route not found");
}

// ================= HANDLER =================
export const handler = async (event) => {
  try {
    return await routeHttp(event);
  } catch (error) {
    console.error("Unhandled error", error);

    if (error?.name === "ConditionalCheckFailedException") {
      return conflict("Resource already exists");
    }

    return serverError("Internal server error", error);
  }
};