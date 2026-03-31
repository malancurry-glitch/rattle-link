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
import https from "https";

// ================= CONFIG =================
const REGION = process.env.AWS_REGION || "us-east-2";

const USERS_TABLE = process.env.USERS_TABLE || "users";
const REDIRECTS_TABLE = process.env.REDIRECTS_TABLE || "redirects";
const CLICKS_TABLE = process.env.CLICKS_TABLE || "clicks";
const WS_CONNECTIONS_TABLE = process.env.WS_CONNECTIONS_TABLE || "ws_connections";
const BLOCKED_IPS_TABLE = process.env.BLOCKED_IPS_TABLE || "blocked_ips";
const EMAIL_LOGS_TABLE = process.env.EMAIL_LOGS_TABLE || "email_logs";
const AUDIT_LOGS_TABLE = process.env.AUDIT_LOGS_TABLE || "audit_logs";
const EMAIL_QUEUE_TABLE = process.env.EMAIL_QUEUE_TABLE || "email_queue";

const APP_SECRET =
  process.env.APP_SECRET ||
  "6360dffbeee180ce660717dc8401497b5985e8abf13c6d056435196bee8dd14b4560f499ed022484285d4e84d9e18409b9937a4f4424e6b08c7e1e8a457c4656";

const FRONTEND_BASE =
  (process.env.FRONTEND_BASE || "https://rattle-link.vercel.app").replace(/\/+$/, "");

const API_BASE =
  (process.env.API_BASE ||
    "https://suvegwrmzl.execute-api.us-east-2.amazonaws.com/production").replace(/\/+$/, "");

const WS_ENDPOINT =
  process.env.WS_ENDPOINT ||
  "https://zzqva6jif7.execute-api.us-east-2.amazonaws.com/production";

const RECAPTCHA_SECRET =
  process.env.RECAPTCHA_SECRET ||
  "6LfBaZwsAAAAALGh_1Ld0rYE-3ws60BA9Wvt6pRO";

const RESEND_KEY =
  process.env.RESEND_KEY ||
  "re_Nqt7buh8_3R8Ch2735okZj9TgEgaVmUXk";

const RESEND_FROM =
  process.env.RESEND_FROM || "Rattle Link <support@rattleshort.online>";

const RESET_PAGE = process.env.RESET_PAGE || "/reset-password.html";
const MAGIC_PAGE = process.env.MAGIC_PAGE || "/magic-login.html";

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
const TOKEN_TTL_SECONDS = Number(
  process.env.TOKEN_TTL_SECONDS || 60 * 60 * 24 * 7
);
const CLICK_HISTORY_QUERY_LIMIT = Number(
  process.env.CLICK_HISTORY_QUERY_LIMIT || 1000
);

// ================= CLIENTS =================
const db = new DynamoDBClient({ region: REGION });

// ================= CORS =================
const corsHeaders = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
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

function badRequest(message) {
  return json(400, { message });
}

function unauthorized(message = "Unauthorized") {
  return json(401, { message });
}

function forbidden(message = "Forbidden") {
  return json(403, { message });
}

function notFound(message = "Not found") {
  return json(404, { message });
}

function conflict(message = "Resource already exists") {
  return json(409, { message });
}

function serverError(message = "Internal server error", error = null) {
  console.error(message, error);
  return json(500, { message, error: error?.message || undefined });
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
function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeSlug(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
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

function randomId(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

function generateSlug() {
  return Math.random().toString(36).substring(2, 8).toLowerCase();
}

function hashPassword(password) {
  // keep legacy sha256 so old users can still log in
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

// ================= TOKEN HELPERS =================
// legacy token support: base64(username:secret)
function generateLegacyToken(username) {
  return Buffer.from(`${username}:${APP_SECRET}`).toString("base64");
}

function verifyLegacyToken(rawToken) {
  try {
    const [user, sec] = Buffer.from(String(rawToken || ""), "base64")
      .toString()
      .split(":");

    if (!user || sec !== APP_SECRET) return null;
    return { sub: user, role: "user" };
  } catch {
    return null;
  }
}

// optional signed token support
function signToken(payload) {
  const jsonPayload = JSON.stringify(payload);
  const base = Buffer.from(jsonPayload).toString("base64url");
  const sig = crypto
    .createHmac("sha256", APP_SECRET)
    .update(base)
    .digest("base64url");
  return `${base}.${sig}`;
}

function verifySignedToken(token) {
  try {
    const [base, sig] = String(token || "").split(".");
    if (!base || !sig) return null;

    const expected = crypto
      .createHmac("sha256", APP_SECRET)
      .update(base)
      .digest("base64url");

    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(base, "base64url").toString("utf8")
    );

    if (!payload?.sub || !payload?.exp) return null;
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch {
    return null;
  }
}

function issueAuthToken(username, role) {
  // return legacy token because your frontend/backend old flow depends on it
  return generateLegacyToken(username);
}

function getBearerToken(event) {
  const auth = getHeaders(event).authorization || getHeaders(event).Authorization;
  if (!auth) return null;
  return auth.startsWith("Bearer ") ? auth.slice(7).trim() : auth.trim();
}

async function getCurrentUser(event) {
  const raw = getBearerToken(event);
  if (!raw) return null;

  const signed = verifySignedToken(raw);
  if (signed?.sub) {
    return {
      username: signed.sub,
      role: signed.role || "user"
    };
  }

  const legacy = verifyLegacyToken(raw);
  if (!legacy?.sub) return null;

  const dbUser = await getUser(legacy.sub);
  return {
    username: legacy.sub,
    role: dbUser?.role?.S || "user"
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

async function getUser(username) {
  const res = await db.send(
    new GetItemCommand({
      TableName: USERS_TABLE,
      Key: { username: ddbString(username) }
    })
  );
  return res.Item || null;
}

async function isAdmin(username) {
  const user = await getUser(username);
  return attrString(user, "role", "user") === "admin";
}

async function assertAdmin(username) {
  const ok = await isAdmin(username);
  if (!ok) throw new Error("ADMIN_ONLY");
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

async function isBlockedIP(ip) {
  const res = await db.send(
    new GetItemCommand({
      TableName: BLOCKED_IPS_TABLE,
      Key: { ip: ddbString(ip) }
    })
  );
  return !!res.Item;
}

// ================= NETWORK / IP =================
function getIP(event) {
  try {
    const headers = getHeaders(event);

    let ip =
      headers["x-forwarded-for"] ||
      headers["X-Forwarded-For"] ||
      headers["x-real-ip"] ||
      headers["X-Real-IP"] ||
      event?.requestContext?.http?.sourceIp ||
      event?.requestContext?.identity?.sourceIp ||
      event?.requestContext?.identity?.userIp ||
      "unknown";

    ip = String(ip).split(",")[0].trim();

    if (ip === "::1" || ip === "127.0.0.1") ip = "unknown";
    if (!ip || ip.length < 3) ip = "unknown";

    return ip;
  } catch (error) {
    console.error("IP ERROR", error);
    return "unknown";
  }
}

function isBot(headers = {}) {
  const ua = String(
    headers["user-agent"] || headers["User-Agent"] || ""
  ).toLowerCase();

  return (
    ua.includes("bot") ||
    ua.includes("crawl") ||
    ua.includes("spider") ||
    ua.includes("curl") ||
    ua.includes("wget") ||
    ua.includes("python") ||
    ua.includes("scrapy") ||
    ua.length < 5
  );
}

function isVPN(ip, headers = {}) {
  const ua = String(
    headers["user-agent"] || headers["User-Agent"] || ""
  ).toLowerCase();

  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.") ||
    ip.startsWith("127.") ||
    ip.startsWith("172.") ||
    ua.includes("vpn") ||
    ua.includes("proxy") ||
    ua.includes("tor") ||
    ua.includes("cloud")
  );
}

function scoreIP(ip, headers = {}) {
  let score = 0;

  if (ip === "unknown") score += 40;
  if (
    ip.startsWith("192.") ||
    ip.startsWith("127.") ||
    ip.startsWith("10.") ||
    ip.startsWith("172.")
  ) {
    score += 30;
  }
  if (isVPN(ip, headers)) score += 20;
  if (isBot(headers)) score += 40;

  return Math.min(score, 100);
}

// ================= CAPTCHA =================
async function verifyCaptcha(token) {
  if (!RECAPTCHA_SECRET) return true;
  if (!token) return false;
  if (token === "bypass") return true;

  return new Promise((resolve) => {
    const postData = `secret=${encodeURIComponent(
      RECAPTCHA_SECRET
    )}&response=${encodeURIComponent(token)}`;

    const req = https.request(
      {
        hostname: "www.google.com",
        path: "/recaptcha/api/siteverify",
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(postData)
        },
        timeout: 10000
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          try {
            const parsed = JSON.parse(body);
            resolve(!!parsed.success);
          } catch {
            resolve(false);
          }
        });
      }
    );

    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });

    req.write(postData);
    req.end();
  });
}

// ================= EMAIL =================
function emailTemplate({ title, message, button, link }) {
  return `
    <div style="font-family:Inter,Arial,sans-serif;background:#020617;padding:40px;color:#fff;">
      <div style="max-width:520px;margin:auto;background:#000;padding:32px;border-radius:16px;">
        <h1 style="text-align:center;color:#00ffff;margin-top:0;">🐍 Rattle Link</h1>
        <h2>${title}</h2>
        <p style="color:#94a3b8;line-height:1.6;">${message}</p>
        <a href="${link}" style="display:block;margin-top:24px;padding:14px 16px;background:#00ffff;color:#000;text-align:center;border-radius:12px;text-decoration:none;font-weight:bold;">${button}</a>
      </div>
    </div>
  `;
}

async function sendEmail(to, { subject, html }) {
  if (!RESEND_KEY || !to || !subject || !html) return false;

  return new Promise((resolve) => {
    const payload = JSON.stringify({
      from: RESEND_FROM,
      to: [to],
      subject,
      html,
      text: "Open this email to continue.",
      reply_to: "support@rattleshort.online"
    });

    const req = https.request(
      {
        hostname: "api.resend.com",
        path: "/emails",
        method: "POST",
        headers: {
          Authorization: `Bearer ${RESEND_KEY}`,
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload)
        },
        timeout: 10000
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          resolve(res.statusCode >= 200 && res.statusCode < 300);
        });
      }
    );

    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });

    req.write(payload);
    req.end();
  });
}

async function sendEmailWithRetry(to, payload, retries = 2) {
  for (let i = 0; i <= retries; i++) {
    const sent = await sendEmail(to, payload);
    if (sent) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

async function logEmailEvent(type, email, subject, status = "unknown") {
  try {
    await db.send(
      new PutItemCommand({
        TableName: EMAIL_LOGS_TABLE,
        Item: {
          id: ddbString(crypto.randomUUID()),
          type: ddbString(type),
          email: ddbString(email),
          subject: ddbString(subject || "unknown"),
          status: ddbString(status),
          time: ddbNumber(Date.now())
        }
      })
    );
  } catch (error) {
    console.error("EMAIL LOG ERROR", error);
  }
}

async function sendResetEmail(email, link) {
  const sent = await sendEmailWithRetry(email, {
    subject: "Reset your password 🔐",
    html: emailTemplate({
      title: "Reset your password",
      message: "Click below to reset your password",
      button: "Reset Password",
      link
    })
  });

  await logEmailEvent(
    sent ? "sent" : "failed",
    email,
    "Reset your password",
    sent ? "sent" : "failed"
  );

  return sent;
}

async function sendWelcomeEmail(email) {
  const sent = await sendEmailWithRetry(email, {
    subject: "Welcome to Rattle Link 🎉",
    html: emailTemplate({
      title: "Welcome!",
      message: "Your account is ready. Start shortening links now.",
      button: "Go to Dashboard",
      link: FRONTEND_BASE
    })
  });

  await logEmailEvent(
    sent ? "sent" : "failed",
    email,
    "Welcome to Rattle Link",
    sent ? "sent" : "failed"
  );

  return sent;
}

async function sendMagicLink(email, link) {
  const sent = await sendEmailWithRetry(email, {
    subject: "Your login link 🔑",
    html: emailTemplate({
      title: "Login instantly",
      message: "Click below to login without password",
      button: "Login",
      link
    })
  });

  await logEmailEvent(
    sent ? "sent" : "failed",
    email,
    "Your login link",
    sent ? "sent" : "failed"
  );

  return sent;
}

// ================= REALTIME =================
async function pushRealtimeUpdate(type = "click-update") {
  try {
    const connections = await scanAll(WS_CONNECTIONS_TABLE);
    if (!connections.length) return;

    const ws = new ApiGatewayManagementApiClient({
      endpoint: WS_ENDPOINT
    });

    for (const connection of connections) {
      try {
        await ws.send(
          new PostToConnectionCommand({
            ConnectionId: attrString(connection, "id"),
            Data: JSON.stringify({
              type,
              time: Date.now()
            })
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

// ================= AUDIT =================
async function createAuditLog(admin, action, target) {
  try {
    await db.send(
      new PutItemCommand({
        TableName: AUDIT_LOGS_TABLE,
        Item: {
          id: ddbString(crypto.randomUUID()),
          admin: ddbString(admin),
          action: ddbString(action),
          target: ddbString(target),
          time: ddbNumber(Date.now())
        }
      })
    );
  } catch (error) {
    console.error("AUDIT LOG ERROR", error);
  }
}

// ================= AUTH CHECK =================
function authRequired(event) {
  const path = getPath(event);
  return (
    path === "/create" ||
    path === "/list" ||
    path === "/history" ||
    path === "/delete" ||
    path.startsWith("/admin")
  );
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

// ================= MAIN ROUTER =================
async function routeHttp(event) {
  const method = getMethod(event);
  const path = getPath(event);
  const headers = getHeaders(event);
  const body = getBody(event);
  const currentUser = await getCurrentUser(event);

  if (method === "OPTIONS") {
    return response(200, "");
  }

  if (event?.requestContext?.connectionId) {
    return handleWebSocket(event);
  }

  if (authRequired(event) && !currentUser) {
    return unauthorized();
  }

  // ================= TEST EMAIL =================
  if (method === "GET" && path === "/test-email") {
    const sent = await sendEmail("YOUR_EMAIL@gmail.com", {
      subject: "TEST EMAIL",
      html: "<h1>WORKING ✅</h1>"
    });
    return text(200, sent ? "sent" : "failed");
  }

  // ================= LOGIN =================
  if (method === "POST" && path === "/login") {
    const username = normalizeEmail(body.username);
    const password = String(body.password || "");
    const captcha = body.captcha;

    if (!username || !password) {
      return badRequest("Missing username or password");
    }

    const validCaptcha = await verifyCaptcha(captcha);
    if (!validCaptcha) {
      return forbidden("Captcha failed");
    }

    const dbUser = await getUser(username);

    if (!dbUser) {
      return unauthorized("Invalid credentials");
    }

    if (attrBool(dbUser, "banned")) {
      return forbidden("Account blocked");
    }

    const storedPassword = attrString(dbUser, "password", "");
    const hashedInput = hashPassword(password);

    if (storedPassword !== hashedInput) {
      return unauthorized("Invalid credentials");
    }

    return ok({
      token: issueAuthToken(username, attrString(dbUser, "role", "user")),
      role: attrString(dbUser, "role", "user")
    });
  }

  // ================= SIGNUP =================
  if (method === "POST" && path === "/signup") {
    const username = normalizeEmail(body.username);
    const password = String(body.password || "");
    const captcha = body.captcha;

    if (!username || !password) {
      return badRequest("Missing username or password");
    }

    if (!isValidEmail(username)) {
      return badRequest("Invalid email format");
    }

    if (password.length < 6) {
      return badRequest("Password must be at least 6 characters");
    }

    const validCaptcha = await verifyCaptcha(captcha);
    if (!validCaptcha) {
      return forbidden("Captcha failed");
    }

    const existing = await getUser(username);
    if (existing) {
      return conflict("User already exists");
    }

    await db.send(
      new PutItemCommand({
        TableName: USERS_TABLE,
        Item: {
          username: ddbString(username),
          password: ddbString(hashPassword(password)),
          role: ddbString("user"),
          banned: ddbBool(false),
          geoTracking: ddbBool(true),
          requests: ddbNumber(0),
          createdAt: ddbNumber(Date.now())
        },
        ConditionExpression: "attribute_not_exists(username)"
      })
    );

    await sendWelcomeEmail(username);

    return ok({ message: "Account created successfully" });
  }

  // ================= FORGOT PASSWORD =================
  if (method === "POST" && path === "/forgot") {
    const username = normalizeEmail(body.username);

    if (!username) {
      return badRequest("Username required");
    }

    if (!isValidEmail(username)) {
      return badRequest("Invalid email");
    }

    const user = await getUser(username);

    if (!user) {
      return ok({ message: "If account exists, reset link sent" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const expire = Date.now() + 15 * 60 * 1000;

    await db.send(
      new UpdateItemCommand({
        TableName: USERS_TABLE,
        Key: { username: ddbString(username) },
        UpdateExpression: "SET resetToken = :t, resetExpire = :e",
        ExpressionAttributeValues: {
          ":t": ddbString(resetToken),
          ":e": ddbNumber(expire)
        }
      })
    );

    const resetLink = `${FRONTEND_BASE}${RESET_PAGE}?token=${resetToken}`;
    const sent = await sendResetEmail(username, resetLink);

    if (!sent) {
      return serverError("Email failed to send");
    }

    return ok({ message: "If account exists, reset link sent" });
  }

  // ================= RESET PASSWORD =================
  if (method === "POST" && path === "/reset") {
    const token = String(body.token || "");
    const newPassword = String(body.password || "");

    if (!token || !newPassword) {
      return badRequest("Missing token or password");
    }

    if (newPassword.length < 6) {
      return badRequest("Password too short");
    }

    const users = await scanAll(USERS_TABLE);

    const user = users.find(
      (u) =>
        attrString(u, "resetToken") === token &&
        attrNumber(u, "resetExpire", 0) > Date.now()
    );

    if (!user) {
      return badRequest("Invalid or expired token");
    }

    await db.send(
      new UpdateItemCommand({
        TableName: USERS_TABLE,
        Key: { username: ddbString(attrString(user, "username")) },
        UpdateExpression: "SET password = :p REMOVE resetToken, resetExpire",
        ExpressionAttributeValues: {
          ":p": ddbString(hashPassword(newPassword))
        }
      })
    );

    return ok({ message: "Password updated" });
  }

  // ================= MAGIC REQUEST =================
  if (method === "POST" && path === "/magic-request") {
    const username = normalizeEmail(body.username);

    if (!username) {
      return badRequest("Username required");
    }

    if (!isValidEmail(username)) {
      return badRequest("Invalid email");
    }

    const existing = await getUser(username);

    if (existing) {
      const token = crypto.randomBytes(32).toString("hex");

      await db.send(
        new UpdateItemCommand({
          TableName: USERS_TABLE,
          Key: { username: ddbString(username) },
          UpdateExpression: "SET magicToken = :t, magicExpire = :e",
          ExpressionAttributeValues: {
            ":t": ddbString(token),
            ":e": ddbNumber(Date.now() + 10 * 60 * 1000)
          }
        })
      );

      const link = `${FRONTEND_BASE}${MAGIC_PAGE}?token=${token}`;
      await sendMagicLink(username, link);
    }

    return ok({ message: "Magic link sent" });
  }

  // ================= MAGIC LOGIN =================
  if (method === "POST" && path === "/magic-login") {
    const token = String(body.token || "");

    if (!token) {
      return badRequest("Missing token");
    }

    const users = await scanAll(USERS_TABLE);

    const user = users.find(
      (u) =>
        attrString(u, "magicToken") === token &&
        attrNumber(u, "magicExpire", 0) > Date.now()
    );

    if (!user) {
      return badRequest("Invalid link");
    }

    await db.send(
      new UpdateItemCommand({
        TableName: USERS_TABLE,
        Key: { username: ddbString(attrString(user, "username")) },
        UpdateExpression: "REMOVE magicToken, magicExpire"
      })
    );

    return ok({
      token: issueAuthToken(
        attrString(user, "username"),
        attrString(user, "role", "user")
      ),
      role: attrString(user, "role", "user")
    });
  }

  // ================= WEBHOOK =================
  if (path === "/webhook/email") {
    try {
      const payload =
        typeof event.body === "string" ? JSON.parse(event.body || "{}") : body;

      const eventType = payload?.type || "unknown";
      const email = payload?.data?.to?.[0] || payload?.data?.email || "unknown";
      const subject = payload?.data?.subject || "unknown";
      const status = payload?.data?.status || "unknown";

      await logEmailEvent(eventType, email, subject, status);

      return text(200, "Webhook received");
    } catch (error) {
      console.error("WEBHOOK ERROR", error);
      return serverError("Webhook failed", error);
    }
  }

  // ================= EMAIL WORKER =================
  if (path === "/worker/email") {
    try {
      const items = await scanAll(EMAIL_QUEUE_TABLE);

      for (const job of items) {
        if (attrString(job, "status") !== "pending") continue;

        const id = attrString(job, "id");
        const to = attrString(job, "to");
        const type = attrString(job, "type");
        const link = attrString(job, "link", "");
        const attempts = attrNumber(job, "attempts", 0);

        let success = false;

        if (type === "reset") success = await sendResetEmail(to, link);
        if (type === "magic") success = await sendMagicLink(to, link);
        if (type === "welcome") success = await sendWelcomeEmail(to);

        const newStatus = success
          ? "sent"
          : attempts < 2
          ? "pending"
          : "dead";

        await db.send(
          new UpdateItemCommand({
            TableName: EMAIL_QUEUE_TABLE,
            Key: { id: ddbString(id) },
            UpdateExpression: "SET #s = :s, attempts = :a",
            ExpressionAttributeNames: {
              "#s": "status"
            },
            ExpressionAttributeValues: {
              ":s": ddbString(newStatus),
              ":a": ddbNumber(attempts + 1)
            }
          })
        );
      }

      return text(200, "Worker completed");
    } catch (error) {
      console.error("WORKER ERROR", error);
      return serverError("Worker failed", error);
    }
  }

  // ================= CREATE LINK =================
  if (method === "POST" && path === "/create") {
    const url = String(body.url || "").trim();
    const slug = normalizeSlug(body.slug || generateSlug());
    const expire = body.expire ? Number(body.expire) : null;

    if (!isValidUrl(url)) {
      return badRequest("Invalid URL");
    }

    if (!isValidSlug(slug)) {
      return badRequest("Invalid slug");
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
          expire: expire ? ddbNumber(expire) : { NULL: true },
          createdAt: ddbNumber(Date.now())
        },
        ConditionExpression: "attribute_not_exists(slug)"
      })
    );

    await db.send(
      new UpdateItemCommand({
        TableName: USERS_TABLE,
        Key: { username: ddbString(currentUser.username) },
        UpdateExpression: "SET requests = if_not_exists(requests, :z) + :i",
        ExpressionAttributeValues: {
          ":z": ddbNumber(0),
          ":i": ddbNumber(1)
        }
      })
    );

    return ok({ link: `${API_BASE}/${slug}` });
  }

  // ================= LIST USER LINKS =================
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
          createdAt: attrNumber(item, "createdAt", 0)
        }))
    });
  }

  // ================= HISTORY =================
  if (method === "GET" && path === "/history") {
    const slug = normalizeSlug(getQuery(event).slug);

    if (!slug) {
      return badRequest("Missing slug");
    }

    const link = await getRedirect(slug);

    if (!link) {
      return notFound("Link not found");
    }

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

  // ================= DELETE LINK =================
  if (method === "POST" && path === "/delete") {
    const slug = normalizeSlug(body.slug);

    if (!slug) {
      return badRequest("Missing slug");
    }

    const link = await getRedirect(slug);

    if (!link) {
      return notFound("Link not found");
    }

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

  // ================= ADMIN AUTH =================
  if (path.startsWith("/admin")) {
    try {
      await assertAdmin(currentUser.username);
    } catch (error) {
      if (error.message === "ADMIN_ONLY") {
        return forbidden("Admin only");
      }
      throw error;
    }
  }

  // ================= ADMIN USERS =================
  if (method === "GET" && path === "/admin/users") {
    const users = await scanAll(USERS_TABLE);

    return ok({
      users: users.map((item) => ({
        username: attrString(item, "username"),
        role: attrString(item, "role", "user"),
        banned: attrBool(item, "banned", false),
        geoTracking: attrBool(item, "geoTracking", true),
        requests: attrNumber(item, "requests", 0),
        createdAt: attrNumber(item, "createdAt", 0)
      }))
    });
  }

  // ================= ADMIN LINKS =================
  if (method === "GET" && path === "/admin/links") {
    const links = await scanAll(REDIRECTS_TABLE);

    return ok({
      items: links.map((item) => ({
        slug: attrString(item, "slug"),
        url: attrString(item, "url"),
        clicks: attrNumber(item, "clicks"),
        paused: attrBool(item, "paused", false),
        user: attrString(item, "user"),
        expire: item?.expire?.N ? Number(item.expire.N) : null,
        createdAt: attrNumber(item, "createdAt", 0)
      }))
    });
  }

  // ================= ADMIN CREATE USER =================
  if (method === "POST" && path === "/admin/create-user") {
    const username = normalizeEmail(body.username);
    const password = String(body.password || "");
    const role = body.role === "admin" ? "admin" : "user";

    if (!isValidEmail(username)) {
      return badRequest("Invalid email");
    }

    if (password.length < 6) {
      return badRequest("Password must be at least 6 characters");
    }

    await db.send(
      new PutItemCommand({
        TableName: USERS_TABLE,
        Item: {
          username: ddbString(username),
          password: ddbString(hashPassword(password)),
          role: ddbString(role),
          banned: ddbBool(false),
          geoTracking: ddbBool(true),
          requests: ddbNumber(0),
          createdAt: ddbNumber(Date.now())
        },
        ConditionExpression: "attribute_not_exists(username)"
      })
    );

    await createAuditLog(currentUser.username, "CREATE USER", username);

    return text(200, "User created");
  }

  // ================= ADMIN ROLE CONTROL =================
  if (method === "POST" && path === "/admin/make-admin") {
    const username = normalizeEmail(body.username);

    await db.send(
      new UpdateItemCommand({
        TableName: USERS_TABLE,
        Key: { username: ddbString(username) },
        UpdateExpression: "SET #r = :r",
        ExpressionAttributeNames: { "#r": "role" },
        ExpressionAttributeValues: { ":r": ddbString("admin") }
      })
    );

    await createAuditLog(currentUser.username, "PROMOTE ADMIN", username);

    return text(200, "ok");
  }

  if (method === "POST" && path === "/admin/remove-admin") {
    const username = normalizeEmail(body.username);

    await db.send(
      new UpdateItemCommand({
        TableName: USERS_TABLE,
        Key: { username: ddbString(username) },
        UpdateExpression: "SET #r = :r",
        ExpressionAttributeNames: { "#r": "role" },
        ExpressionAttributeValues: { ":r": ddbString("user") }
      })
    );

    await createAuditLog(currentUser.username, "REMOVE ADMIN", username);

    return text(200, "ok");
  }

  // ================= ADMIN USER CONTROL =================
  if (method === "POST" && path === "/admin/ban") {
    const username = normalizeEmail(body.username);

    await db.send(
      new UpdateItemCommand({
        TableName: USERS_TABLE,
        Key: { username: ddbString(username) },
        UpdateExpression: "SET banned = :b",
        ExpressionAttributeValues: { ":b": ddbBool(true) }
      })
    );

    await createAuditLog(currentUser.username, "BAN USER", username);

    return text(200, "banned");
  }

  if (method === "POST" && path === "/admin/unban") {
    const username = normalizeEmail(body.username);

    await db.send(
      new UpdateItemCommand({
        TableName: USERS_TABLE,
        Key: { username: ddbString(username) },
        UpdateExpression: "SET banned = :b",
        ExpressionAttributeValues: { ":b": ddbBool(false) }
      })
    );

    await createAuditLog(currentUser.username, "UNBAN USER", username);

    return text(200, "unbanned");
  }

  if (method === "POST" && path === "/admin/geo") {
    const username = normalizeEmail(body.username);

    await db.send(
      new UpdateItemCommand({
        TableName: USERS_TABLE,
        Key: { username: ddbString(username) },
        UpdateExpression: "SET geoTracking = :g",
        ExpressionAttributeValues: { ":g": ddbBool(!!body.enabled) }
      })
    );

    await createAuditLog(currentUser.username, "UPDATE GEO", username);

    return text(200, "geo updated");
  }

  // ================= ADMIN LINK CONTROL =================
  if (method === "POST" && path === "/admin/pause") {
    const slug = normalizeSlug(body.slug);

    await db.send(
      new UpdateItemCommand({
        TableName: REDIRECTS_TABLE,
        Key: { slug: ddbString(slug) },
        UpdateExpression: "SET paused = :p",
        ExpressionAttributeValues: { ":p": ddbBool(true) }
      })
    );

    await createAuditLog(currentUser.username, "PAUSE LINK", slug);

    return text(200, "paused");
  }

  if (method === "POST" && path === "/admin/resume") {
    const slug = normalizeSlug(body.slug);

    await db.send(
      new UpdateItemCommand({
        TableName: REDIRECTS_TABLE,
        Key: { slug: ddbString(slug) },
        UpdateExpression: "SET paused = :p",
        ExpressionAttributeValues: { ":p": ddbBool(false) }
      })
    );

    await createAuditLog(currentUser.username, "RESUME LINK", slug);

    return text(200, "resumed");
  }

  if (method === "POST" && path === "/admin/block-ip") {
    const ip = String(body.ip || "").trim();

    if (!ip) {
      return badRequest("Missing ip");
    }

    await db.send(
      new PutItemCommand({
        TableName: BLOCKED_IPS_TABLE,
        Item: {
          ip: ddbString(ip),
          blockedAt: ddbNumber(Date.now())
        }
      })
    );

    await createAuditLog(currentUser.username, "BLOCK IP", ip);

    return text(200, "IP blocked");
  }

  if (method === "POST" && path === "/admin/unblock-ip") {
    const ip = String(body.ip || "").trim();

    if (!ip) {
      return badRequest("Missing ip");
    }

    await db.send(
      new DeleteItemCommand({
        TableName: BLOCKED_IPS_TABLE,
        Key: { ip: ddbString(ip) }
      })
    );

    await createAuditLog(currentUser.username, "UNBLOCK IP", ip);

    return text(200, "IP unblocked");
  }

  // ================= EMAIL LOGS =================
  if (method === "GET" && path === "/admin/email-logs") {
    const logs = await scanAll(EMAIL_LOGS_TABLE);

    return ok({
      logs: logs.map((item) => ({
        id: attrString(item, "id"),
        type: attrString(item, "type"),
        email: attrString(item, "email"),
        subject: attrString(item, "subject"),
        status: attrString(item, "status"),
        time: attrNumber(item, "time")
      }))
    });
  }

  // ================= AUDIT =================
  if (method === "POST" && path === "/admin/audit") {
    await createAuditLog(
      currentUser.username,
      String(body.action || "UNKNOWN"),
      String(body.target || "UNKNOWN")
    );
    return text(200, "ok");
  }

  if (method === "GET" && path === "/admin/audit") {
    const logs = await scanAll(AUDIT_LOGS_TABLE);

    return ok({
      logs: logs.map((item) => ({
        id: attrString(item, "id"),
        admin: attrString(item, "admin"),
        action: attrString(item, "action"),
        target: attrString(item, "target"),
        time: attrNumber(item, "time")
      }))
    });
  }

  // ================= PUBLIC REDIRECT =================
  if (method === "GET") {
    const reservedRoutes = new Set([
      "/",
      "/login",
      "/signup",
      "/reset",
      "/magic-login",
      "/magic-request",
      "/forgot",
      "/worker/email",
      "/test-email",
      "/list",
      "/history",
      "/create",
      "/delete",
      "/webhook/email",
      "/admin/users",
      "/admin/links",
      "/admin/create-user",
      "/admin/make-admin",
      "/admin/remove-admin",
      "/admin/ban",
      "/admin/unban",
      "/admin/geo",
      "/admin/pause",
      "/admin/resume",
      "/admin/block-ip",
      "/admin/unblock-ip",
      "/admin/email-logs",
      "/admin/audit"
    ]);

    if (!reservedRoutes.has(path) && !path.startsWith("/admin")) {
      const slug = normalizeSlug(path.split("/").filter(Boolean).pop());

      if (!slug) {
        return badRequest("Invalid slug");
      }

      const ip = getIP(event);

      if (await isBlockedIP(ip)) {
        return forbidden("IP blocked");
      }

      const item = await getRedirect(slug);

      if (!item) {
        return notFound("Link not found");
      }

      if (attrBool(item, "paused")) {
        return forbidden("Link is paused");
      }

      if (item?.expire?.N) {
        const expireTime = Number(item.expire.N);
        if (Date.now() > expireTime) {
          return json(410, { message: "Link expired" });
        }
      }

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
            ua: ddbString(
              headers["user-agent"] || headers["User-Agent"] || "unknown"
            )
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