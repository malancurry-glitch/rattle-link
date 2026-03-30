import {
  DynamoDBClient,
  PutItemCommand,
  ScanCommand,
  DeleteItemCommand,
  UpdateItemCommand,
  GetItemCommand
} from "@aws-sdk/client-dynamodb";

import {
  ApiGatewayManagementApiClient,
  PostToConnectionCommand
} from "@aws-sdk/client-apigatewaymanagementapi";

import crypto from "crypto";
import https from "https";

// ================= CLIENTS =================
const client = new DynamoDBClient({ region: "us-east-2" });
const SECRET = "my-secret-key";
const BASE_URL = "https://suvegwrmzl.execute-api.us-east-2.amazonaws.com";
const RECAPTCHA_SECRET = "6LfBaZwsAAAAALGh_1Ld0rYE-3ws60BA9Wvt6pRO";
const RESEND_KEY = "re_Nqt7buh8_3R8Ch2735okZj9TgEgaVmUXk";
const endpoint = "https://zzqva6jif7.execute-api.us-east-2.amazonaws.com/production";

// ================= UTILS =================
function hash(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function generateToken(username) {
  return Buffer.from(username + ":" + SECRET).toString("base64");
}

function verifyToken(event) {
  const auth = event.headers?.authorization || event.headers?.Authorization;
  if (!auth) return null;

  try {
    const token = auth.startsWith("Bearer ") ? auth.split(" ")[1] : auth;
    const [user, sec] = Buffer.from(token, "base64").toString().split(":");
    if (sec !== SECRET) return null;
    return user;
  } catch {
    return null;
  }
}

// SAFE BODY
function getBody(event){
  try { return JSON.parse(event.body || "{}"); }
  catch { return {}; }
}

// ================= REAL IP (FINAL FIXED) =================
function getIP(event){

  try {

    const headers = event.headers || {};

    let ip =
      headers["x-forwarded-for"] ||
      headers["X-Forwarded-For"] ||
      headers["x-real-ip"] ||
      headers["X-Real-IP"] ||
      event.requestContext?.http?.sourceIp ||
      event.requestContext?.identity?.sourceIp ||
      event.requestContext?.identity?.userIp ||
      "";

    // 🔥 ensure string
    if(typeof ip !== "string"){
      ip = String(ip || "");
    }

    // 🔥 handle multiple IPs (proxy chain)
    ip = ip.split(",")[0].trim();

    // 🔥 normalize localhost
    if(ip === "::1" || ip === "127.0.0.1"){
      ip = "unknown";
    }

    // 🔥 final fallback
    if(!ip || ip.length < 3){
      ip = "unknown";
    }

    console.log("FINAL IP:", ip);

    return ip;

  } catch (e){
    console.error("IP ERROR:", e);
    return "unknown";
  }
}

// ================= VPN DETECTION =================
function isVPN(ip, headers = {}){

  const ua = (headers["user-agent"] || "").toLowerCase();

  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.") ||
    ip.startsWith("127.") ||
    ua.includes("vpn") ||
    ua.includes("proxy") ||
    ua.includes("cloud")
  );
}

// ================= BOT DETECTION =================
function isBot(headers = {}){

  const ua = (headers["user-agent"] || "").toLowerCase();

  return (
    ua.includes("bot") ||
    ua.includes("crawl") ||
    ua.includes("spider") ||
    ua.includes("curl") ||
    ua.includes("wget") ||
    ua.length < 5
  );
}

// ================= RISK SCORING =================
function scoreIP(ip, headers = {}){

  let score = 0;

  if(ip === "unknown") score += 40;

  if(ip.startsWith("192.") || ip.startsWith("127.") || ip.startsWith("10.")){
    score += 30;
  }

  if(isVPN(ip, headers)) score += 20;

  if(isBot(headers)) score += 40;

  return Math.min(score, 100);
}

// ================= SLUG =================
function generateSlug() {
  return Math.random().toString(36).substring(2, 8);
}

// ================= CORS =================
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
};

async function verifyCaptcha(token){

  if (!token) {
    console.warn("⚠️ No CAPTCHA token provided");
    return false;
  }

  return new Promise((resolve) => {

    const postData = `secret=${RECAPTCHA_SECRET}&response=${token}`;

    const options = {
      hostname: "www.google.com",
      path: "/recaptcha/api/siteverify",
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": postData.length
      }
    };

    const req = https.request(options, (res) => {

      let body = "";

      res.on("data", chunk => body += chunk);

      res.on("end", () => {

        try {

          const data = JSON.parse(body);

          console.log("🧠 CAPTCHA RESPONSE:", data);

          if (!data.success) {
            console.warn("❌ CAPTCHA FAILED:", data["error-codes"]);
            return resolve(false);
          }

          // ✅ DO NOT check score for v2
          resolve(true);

        } catch (err) {
          console.error("❌ CAPTCHA PARSE ERROR:", body);
          resolve(false);
        }

      });
    });

    req.on("error", (err) => {
      console.error("🔥 CAPTCHA REQUEST ERROR:", err);
      resolve(false);
    });

    req.write(postData);
    req.end();
  });
}
function emailTemplate({ title, message, button, link }) {
  return `
    <div style="font-family:Inter;background:#020617;padding:40px;color:#fff;">
      <div style="max-width:520px;margin:auto;background:#000;padding:30px;border-radius:16px;">
        
        <h1 style="text-align:center;color:#0ff;">🐍 Rattle Link</h1>

        <h2>${title}</h2>

        <p style="color:#94a3b8;">${message}</p>

        <a href="${link}" style="
          display:block;
          margin:25px 0;
          padding:14px;
          text-align:center;
          background:#0ff;
          color:#000;
          border-radius:10px;
          font-weight:bold;
          text-decoration:none;
        ">
          ${button}
        </a>

      </div>
    </div>
  `;
}
async function sendEmail(to, { subject, html }) {

  return new Promise((resolve) => {

    const data = JSON.stringify({
      from: "Rattle Link <support@rattleshort.online>",
      to: [to],
      subject,
      html
    });

    const options = {
      hostname: "api.resend.com",
      path: "/emails",
      method: "POST",
      headers: {
        "Authorization": `Bearer ${RESEND_KEY}`,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data)
      }
    };

    const req = https.request(options, (res) => {

      let body = "";

      res.on("data", chunk => body += chunk);

      res.on("end", () => {
        console.log("📨 RESEND:", res.statusCode, body);

        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(true);
        } else {
          resolve(false);
        }
      });
    });

    req.on("error", (err) => {
      console.error("EMAIL ERROR:", err);
      resolve(false);
    });

    req.write(data);
    req.end();
  });
}
async function sendEmailWithRetry(to, payload, retries = 2){

  for (let i = 0; i <= retries; i++) {

    const success = await sendEmail(to, payload);

    if (success) return true;

    console.warn(`⚠️ Retry ${i+1} failed`);

    await new Promise(r => setTimeout(r, 1000));
  }

  console.error("❌ All retries failed");
  return false;
}
async function sendResetEmail(email, link){

  return sendEmailWithRetry(email, {
    subject: "Reset your password 🔐",
    html: emailTemplate({
      title: "Reset your password",
      message: "Click below to reset your password",
      button: "Reset Password",
      link
    })
  });
}async function sendWelcomeEmail(email){

  return sendEmailWithRetry(email, {
    subject: "Welcome to Rattle Link 🎉",
    html: emailTemplate({
      title: "Welcome!",
      message: "Your account is ready. Start shortening links now.",
      button: "Go to Dashboard",
      link: BASE_URL
    })
  });
}
async function sendMagicLink(email, link){

  return sendEmailWithRetry(email, {
    subject: "Your login link 🔑",
    html: emailTemplate({
      title: "Login instantly",
      message: "Click below to login without password",
      button: "Login",
      link
    })
  });
}
async function triggerRealtimeUpdate(){

  try {

    const connections = await client.send(new ScanCommand({
      TableName: "ws_connections"
    }));

    const wsClient = new ApiGatewayManagementApiClient({ endpoint });

    for (const c of connections.Items || []) {

      try {
        await wsClient.send(new PostToConnectionCommand({
          ConnectionId: c.id.S,
          Data: JSON.stringify({
            type: "click-update",
            time: Date.now()
          })
        }));
      } catch (err) {
        console.error("WS PUSH ERROR:", err);
      }
    }

  } catch (e){
    console.error("REALTIME ERROR:", e);
  }
}
// ================= HANDLER =================
export const handler = async (event) => {
  // ================= WEBSOCKET HANDLER =================
const routeKey = event.requestContext?.routeKey;

if (routeKey) {

  const connectionId = event.requestContext.connectionId;

  try {

    // CONNECT
    if (routeKey === "$connect") {
      await client.send(new PutItemCommand({
        TableName: "ws_connections",
        Item: { id: { S: connectionId } }
      }));
      console.log("WS CONNECT:", connectionId);
      return { statusCode: 200 };
    }

    // DISCONNECT
    if (routeKey === "$disconnect") {
      await client.send(new DeleteItemCommand({
        TableName: "ws_connections",
        Key: { id: { S: connectionId } }
      }));
      console.log("WS DISCONNECT:", connectionId);
      return { statusCode: 200 };
    }

    // BROADCAST
    if (routeKey === "broadcast") {

      const connections = await client.send(new ScanCommand({
        TableName: "ws_connections"
      }));

      const wsClient = new ApiGatewayManagementApiClient({ endpoint });

      for (const c of connections.Items || []) {
        try {
          await wsClient.send(new PostToConnectionCommand({
            ConnectionId: c.id.S,
            Data: JSON.stringify({ type: "update" })
          }));
        } catch (err) {
          console.error("WS SEND ERROR:", err);
        }
      }

      console.log("WS BROADCAST DONE");
      return { statusCode: 200 };
    }

    return { statusCode: 200 };

  } catch (err) {
    console.error("WS ERROR:", err);
    return { statusCode: 500 };
  }
}

  const method = event.requestContext?.http?.method || "GET";
  let path = event.requestContext?.http?.path || "/";
  path = path.toLowerCase();
  // 🔥 MOVE HERE
  try {

    // ================= LOGIN =================
if (method === "POST" && path.endsWith("/login")) {

  console.log("🔥 LOGIN ROUTE HIT:", path);

  try {

    let body = {};

    try {
      body = typeof event.body === "string"
        ? JSON.parse(event.body)
        : event.body || {};
    } catch (e) {
      console.error("BODY PARSE ERROR:", event.body);
      return {
        statusCode: 400,
        headers: cors,
        body: JSON.stringify({ message: "Invalid request body" })
      };
    }

    const username = body.username?.trim().toLowerCase();
    const password = body.password;
    const captcha = body.captcha;

    console.log("USERNAME:", username);

    if (!username || !password) {
      return {
        statusCode: 400,
        headers: cors,
        body: JSON.stringify({ message: "Missing username or password" })
      };
    }

    if (!captcha) {
      return {
        statusCode: 400,
        headers: cors,
        body: JSON.stringify({ message: "Captcha required" })
      };
    }

    const validCaptcha = await verifyCaptcha(captcha);

    if (!validCaptcha) {
      return {
        statusCode: 403,
        headers: cors,
        body: JSON.stringify({ message: "Captcha failed" })
      };
    }

    const res = await client.send(new GetItemCommand({
      TableName: "users",
      Key: { username: { S: username } }
    }));

    if (!res.Item) {
      return {
        statusCode: 401,
        headers: cors,
        body: JSON.stringify({ message: "Invalid credentials" })
      };
    }

    if (res.Item.password?.S !== hash(password)) {
      return {
        statusCode: 401,
        headers: cors,
        body: JSON.stringify({ message: "Invalid credentials" })
      };
    }

    if (res.Item.banned?.BOOL) {
      return {
        statusCode: 403,
        headers: cors,
        body: JSON.stringify({ message: "Account blocked" })
      };
    }

    const role = res.Item.role?.S || "user";

    return {
      statusCode: 200,
      headers: cors,
      body: JSON.stringify({
        token: generateToken(username),
        role
      })
    };

  } catch (err) {
    console.error("🔥 LOGIN ERROR:", err);

    return {
      statusCode: 500,
      headers: cors,
      body: JSON.stringify({ message: "Login failed" })
    };
  }
}
  // ================= SIGNUP =================
  if (method === "POST" && path.includes("signup")) {

    try {
  
      const body = getBody(event);
      const username = body.username?.trim().toLowerCase();
      const password = body.password;
  
      // ================= VALIDATION =================
      if (!username || !password || !body.captcha) {
        return {
          statusCode: 400,
          headers: cors,
          body: "Missing fields"
        };
      }
  
      // 🔥 EMAIL VALIDATION
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(username)) {
        return {
          statusCode: 400,
          headers: cors,
          body: "Invalid email format"
        };
      }
  
      // 🔥 PASSWORD VALIDATION
      if (password.length < 6) {
        return {
          statusCode: 400,
          headers: cors,
          body: "Password must be at least 6 characters"
        };
      }
  
      // ================= CAPTCHA =================
      const validCaptcha = await verifyCaptcha(body.captcha);
  
      if (!validCaptcha) {
        return {
          statusCode: 403,
          headers: cors,
          body: "Captcha failed"
        };
      }
  
      // ================= CHECK EXISTING USER =================
      const existing = await client.send(new GetItemCommand({
        TableName: "users",
        Key: { username: { S: username } }
      }));
  
      if (existing.Item) {
        return {
          statusCode: 400,
          headers: cors,
          body: "User already exists"
        };
      }
  
      // ================= CREATE USER =================
      await client.send(new PutItemCommand({
        TableName: "users",
        Item: {
          username: { S: username },
          password: { S: hash(password) },
  
          // 🔥 ADMIN AUTO ASSIGN (CHANGE THIS EMAIL)
          role: { S: username === "howardanthony7268@gmail.com" ? "admin" : "user" },
  
          banned: { BOOL: false },
          createdAt: { N: String(Date.now()) }
        }
      }));
  
      // ================= SUCCESS =================
      return {
        statusCode: 200,
        headers: cors,
        body: JSON.stringify({
          message: "Account created successfully"
        })
      };
  
    } catch (err) {
  
      console.error("🔥 SIGNUP ERROR:", err);
  
      return {
        statusCode: 500,
        headers: cors,
        body: "Signup failed"
      };
    }
  }
      
// ================= RESET PASSWORD =================
if (method === "POST" && path.includes("reset")) {

  try {

    const body = getBody(event);
    const token = body.token;
    const newPassword = body.password;

    if (!token || !newPassword) {
      return { statusCode: 400, headers: cors, body: "Missing token or password" };
    }

    if (newPassword.length < 6) {
      return { statusCode: 400, headers: cors, body: "Password too short" };
    }

    const res = await client.send(new ScanCommand({
      TableName: "users"
    }));

    const user = (res.Items || []).find(u =>
      u.resetToken?.S === token &&
      Number(u.resetExpire?.N || 0) > Date.now()
    );

    // 🔥 IMPORTANT FIX
    if (!user) {
      return { statusCode: 400, headers: cors, body: "Invalid or expired token" };
    }

    await client.send(new UpdateItemCommand({
      TableName: "users",
      Key: { username: { S: user.username.S } },
      UpdateExpression: "SET password = :p REMOVE resetToken, resetExpire",
      ExpressionAttributeValues: {
        ":p": { S: hash(newPassword) }
      }
    }));

    return {
      statusCode: 200,
      headers: cors,
      body: "Password updated"
    };

  } catch (err) {
    console.error("RESET ERROR:", err);
    return { statusCode: 500, headers: cors, body: "Reset failed" };
  }
}

if (method === "POST" && path.includes("magic-login")) {

  const body = getBody(event);
  const token = body.token;

  const res = await client.send(new ScanCommand({
    TableName: "users"
  }));

  const user = (res.Items || []).find(u =>
    u.magicToken?.S === token &&
    Number(u.magicExpire?.N || 0) > Date.now()
  );

  if (!user) {
    return { statusCode: 400, body: "Invalid link" };
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      token: generateToken(user.username.S),
      role: user.role?.S || "user"
    })
  };
}
if (method === "POST" && path.includes("magic-request")) {

  const body = getBody(event);
  const username = body.username?.trim().toLowerCase();

  const token = crypto.randomBytes(32).toString("hex");

  await client.send(new UpdateItemCommand({
    TableName: "users",
    Key: { username: { S: username } },
    UpdateExpression: "SET magicToken = :t, magicExpire = :e",
    ExpressionAttributeValues: {
      ":t": { S: token },
      ":e": { N: String(Date.now() + 10 * 60 * 1000) }
    }
  }));

  const link = `${BASE_URL}/magic-login.html?token=${token}`;

  await sendMagicLink(username, link);

  return {
    statusCode: 200,
    body: "Magic link sent"
  };
}
// ================= RESEND WEBHOOK =================
if (path.includes("webhook/email")) {

  try {

    // 🔥 RAW BODY (important for signature verification)
    const rawBody = event.body || "";
    const headers = event.headers || {};

    // ================= OPTIONAL: VERIFY SIGNATURE =================
    // (recommended for production)
    const signature = headers["resend-signature"] || headers["Resend-Signature"];

    if (!signature) {
      console.warn("⚠️ Missing webhook signature");
    }

    // ================= PARSE BODY =================
    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch (e) {
      console.error("❌ Invalid JSON body:", rawBody);
      return { statusCode: 400, body: "Invalid JSON" };
    }

    console.log("📊 EMAIL EVENT:", payload);

    // ================= EXTRACT DATA =================
    const eventType = payload.type || "unknown";

    const email =
      payload.data?.to?.[0] ||
      payload.data?.email ||
      "unknown";

    const messageId =
      payload.data?.id ||
      crypto.randomUUID();

    const timestamp = Date.now();

    // ================= STORE IN DB =================
    await client.send(new PutItemCommand({
      TableName: "email_logs",
      Item: {
        id: { S: messageId },
        type: { S: eventType },
        email: { S: email },
        time: { N: String(timestamp) },

        // 🔥 EXTRA METADATA (VERY USEFUL)
        subject: { S: payload.data?.subject || "unknown" },
        status: { S: payload.data?.status || "unknown" }
      }
    }));

    // ================= RESPONSE =================
    return {
      statusCode: 200,
      headers: cors,
      body: "Webhook received"
    };

  } catch (err) {

    console.error("🔥 WEBHOOK ERROR:", err);

    return {
      statusCode: 500,
      headers: cors,
      body: "Webhook failed"
    };
  }
}

// ================= REDIRECT =================
if (
  method === "GET" &&
  !path.includes("create") &&
  !path.includes("list") &&
  !path.includes("admin")
) {

  try {

    const parts = path.split("/").filter(Boolean);
    const slug = parts.length ? parts.pop().trim() : null;

    if (!slug) {
      return {
        statusCode: 400,
        headers: cors,
        body: "Invalid slug"
      };
    }

    const headers = event.headers || {};
    const ip = getIP(event);

    console.log("IP:", ip);
    console.log("Slug:", slug);

    // ================= IP BLOCK CHECK =================
    try {
      const blocked = await client.send(new GetItemCommand({
        TableName: "blocked_ips",
        Key: { ip: { S: String(ip || "unknown") } }
      }));

      if (blocked.Item) {
        return {
          statusCode: 403,
          headers: cors,
          body: "IP blocked"
        };
      }
    } catch (e){
      console.error("BLOCK CHECK ERROR:", e);
    }

    // ================= GET LINK =================
    const res = await client.send(new GetItemCommand({
      TableName: "redirects",
      Key: { slug: { S: slug } }
    }));

    if (!res.Item) {
      return {
        statusCode: 404,
        headers: cors,
        body: "Link not found"
      };
    }

    // ================= PAUSE CHECK =================
    if (res.Item.paused?.BOOL) {
      return {
        statusCode: 403,
        headers: cors,
        body: "Link is paused"
      };
    }

    // ================= EXPIRE CHECK =================
    if (res.Item.expire?.N) {
      const expireTime = Number(res.Item.expire.N);

      if (Date.now() > expireTime) {
        return {
          statusCode: 410,
          headers: cors,
          body: "Link expired"
        };
      }
    }

    const url = res.Item.url?.S;

    // ================= CLICK COUNT =================
    try {
      await client.send(new UpdateItemCommand({
        TableName: "redirects",
        Key: { slug: { S: slug } },
        UpdateExpression: "SET clicks = if_not_exists(clicks,:z) + :i",
        ExpressionAttributeValues: {
          ":i": { N: "1" },
          ":z": { N: "0" }
        }
      }));
    } catch (e){
      console.error("CLICK UPDATE ERROR:", e);
    }
    await triggerRealtimeUpdate();
    // ================= STORE CLICK =================
    try {

      const timestamp = Date.now();

      await client.send(new PutItemCommand({
        TableName: "clicks",
        Item: {
          id: { S: `${slug}#${timestamp}#${Math.random().toString(36).slice(2,6)}` },
          slug: { S: slug },
          time: { N: String(timestamp) },
          ip: { S: String(ip || "unknown") },
          vpn: { BOOL: isVPN(ip, headers) },
          bot: { BOOL: isBot(headers) },
          risk: { N: String(scoreIP(ip, headers)) },
          ua: { S: headers["user-agent"] || "unknown" }
        }
      }));

      console.log("CLICK STORED:", slug, ip);

    } catch (e){
      console.error("CLICK STORE ERROR:", e);
    }

    // ================= REDIRECT =================
    return {
      statusCode: 302,
      headers: {
        Location: url,
        ...cors
      }
    };

  } catch (err) {
    console.error("🔥 REDIRECT ERROR:", err);

    return {
      statusCode: 500,
      headers: cors,
      body: "Redirect failed"
    };
  }
}
// ================= FORGOT PASSWORD =================
if (method === "POST" && path.includes("forgot")) {

  try {

    const body = getBody(event);
    const username = body.username?.trim().toLowerCase();

    // ================= VALIDATION =================
    if (!username) {
      return {
        statusCode: 400,
        headers: cors,
        body: JSON.stringify({ message: "Username required" })
      };
    }

    // ================= FIND USER =================
    const res = await client.send(new GetItemCommand({
      TableName: "users",
      Key: { username: { S: username } }
    }));

    // 🔐 DO NOT reveal user existence
    if (!res.Item) {
      return {
        statusCode: 200,
        headers: cors,
        body: JSON.stringify({
          message: "If account exists, reset link sent"
        })
      };
    }

    // ================= GENERATE TOKEN =================
    const resetToken = crypto.randomBytes(32).toString("hex");
    const expire = Date.now() + (15 * 60 * 1000); // 15 min

    // ================= STORE TOKEN =================
    await client.send(new UpdateItemCommand({
      TableName: "users",
      Key: { username: { S: username } },
      UpdateExpression: "SET resetToken = :t, resetExpire = :e",
      ExpressionAttributeValues: {
        ":t": { S: resetToken },
        ":e": { N: String(expire) }
      }
    }));

    // ================= RESET LINK =================
    const resetLink = `https://rattleshort.netlify.app/reset-password.html?token=${resetToken}`;

    console.log("🔗 RESET LINK:", resetLink);

    // ================= SEND EMAIL =================
    console.log("🚀 BEFORE EMAIL");

    const sent = await sendResetEmail(username, resetLink);
    console.log("🚀 AFTER EMAIL:", sent);

    if (!sent) {
      console.error("🚨 EMAIL FAILED TO SEND");
    }

    // ================= RESPONSE =================
    return {
      statusCode: 200,
      headers: cors,
      body: JSON.stringify({
        message: "If account exists, reset link sent"
      })
    };

  } catch (err) {

    console.error("🔥 FORGOT ERROR:", err);

    return {
      statusCode: 500,
      headers: cors,
      body: JSON.stringify({
        message: "Failed to process request"
      })
    };
  }
}
// ================= EMAIL WORKER =================
if (path.includes("worker/email")) {

  try {

    console.log("🚀 Worker started");

    const res = await client.send(new ScanCommand({
      TableName: "email_queue"
    }));

    const items = res.Items || [];

    for (const job of items) {

      if (job.status?.S !== "pending") continue;

      const id = job.id.S;
      const to = job.to.S;
      const type = job.type.S;
      const link = job.link?.S || "";
      const attempts = Number(job.attempts?.N || 0);

      console.log("📨 Processing:", id);

      let success = false;

      try {

        if (type === "reset") {
          success = await sendResetEmail(to, link);
        }

        if (type === "magic") {
          success = await sendMagicLink(to, link);
        }

        if (type === "welcome") {
          success = await sendWelcomeEmail(to);
        }

      } catch (e) {
        console.error("❌ Send error:", e);
      }

      // 🔁 RETRY LOGIC
      let newStatus = "failed";

      if (success) {
        newStatus = "sent";
      } else if (attempts < 2) {
        newStatus = "pending"; // retry later
      } else {
        newStatus = "dead"; // give up
      }

      // ================= UPDATE =================
      await client.send(new UpdateItemCommand({
        TableName: "email_queue",
        Key: { id: { S: id } },
        UpdateExpression: "SET #s = :s, attempts = :a",
        ExpressionAttributeNames: {
          "#s": "status"
        },
        ExpressionAttributeValues: {
          ":s": { S: newStatus },
          ":a": { N: String(attempts + 1) }
        }
      }));

      console.log(`${newStatus.toUpperCase()}:`, id);
    }

    return {
      statusCode: 200,
      headers: cors,
      body: "Worker completed"
    };

  } catch (err) {

    console.error("🔥 WORKER ERROR:", err);

    return {
      statusCode: 500,
      headers: cors,
      body: "Worker failed"
    };
  }
}
  // ================= AUTH =================
    const user = verifyToken(event);
    if (!user) return { statusCode: 401, headers: cors, body: "Unauthorized" };

// ================= CREATE =================
if (method === "POST" && path.includes("create")) {
  const body = getBody(event);

  const slug = body.slug || generateSlug();

  await client.send(new PutItemCommand({
    TableName: "redirects",
    Item: {
      slug: { S: slug },
      url: { S: body.url },
      clicks: { N: "0" },
      paused: { BOOL: false },
      user: { S: user },

      // ✅ EXPIRE FIX (ONLY ADDITION)
      expire: body.expire && !isNaN(body.expire)
        ? { N: String(body.expire) }
        : { NULL: true }
    }
  }));

  return {
    statusCode: 200,
    headers: cors,
    body: JSON.stringify({ link: `${BASE_URL}/${slug}` })
  };
}

// ================= LIST =================
if (method === "GET" && path.includes("list")) {

  const username = verifyToken(event);

  if (!username) {
    return { statusCode: 401, headers: cors, body: "Unauthorized" };
  }

  const res = await client.send(new ScanCommand({
    TableName: "redirects"
  }));

  const items = (res.Items || [])
    .filter(i => i.user?.S === username) // 🔥 ONLY THEIR DATA
    .map(i => ({
      slug: i.slug?.S || "",
      url: i.url?.S || "",
      clicks: Number(i.clicks?.N || 0),
      paused: i.paused?.BOOL || false,
      user: i.user?.S || "",
      expire: i.expire?.N ? Number(i.expire.N) : null
    }));

  return {
    statusCode: 200,
    headers: cors,
    body: JSON.stringify({ items })
  };
}
// ================= HISTORY (SECURE + FINAL) =================
if (method === "GET" && path.includes("history")) {

  const username = verifyToken(event);

  if (!username) {
    return { statusCode: 401, headers: cors, body: "Unauthorized" };
  }

  const rawSlug = event.queryStringParameters?.slug || "";
  const slug = rawSlug.trim().toLowerCase();

  if (!slug) {
    return { statusCode: 400, headers: cors, body: "Missing slug" };
  }

  // 🔒 VERIFY OWNERSHIP
  const link = await client.send(new GetItemCommand({
    TableName: "redirects",
    Key: { slug: { S: slug } }
  }));

  if (!link.Item || link.Item.user?.S !== username) {
    return { statusCode: 403, headers: cors, body: "Forbidden" };
  }

  let allItems = [];
  let lastKey;

  do {
    const res = await client.send(new ScanCommand({
      TableName: "clicks",
      ExclusiveStartKey: lastKey
    }));

    if (res.Items) allItems.push(...res.Items);
    lastKey = res.LastEvaluatedKey;

  } while (lastKey);

  let history = allItems
    .filter(i => (i.slug?.S || "").toLowerCase() === slug)
    .map(i => ({
      time: Number(i.time?.N || Date.now()),
      ip: i.ip?.S || "unknown",
      vpn: i.vpn?.BOOL || false,
      bot: i.bot?.BOOL || false,
      risk: Number(i.risk?.N || 0)
    }))
    .sort((a,b)=>b.time - a.time);

  return {
    statusCode: 200,
    headers: cors,
    body: JSON.stringify({ history })
  };
}


// ================= DELETE (SECURE) =================
if (method === "POST" && path.includes("delete")) {

  const username = verifyToken(event);

  if (!username) {
    return { statusCode: 401, headers: cors, body: "Unauthorized" };
  }

  const body = getBody(event);

  // 🔒 VERIFY OWNERSHIP
  const link = await client.send(new GetItemCommand({
    TableName: "redirects",
    Key: { slug: { S: body.slug } }
  }));

  if (!link.Item || link.Item.user?.S !== username) {
    return { statusCode: 403, headers: cors, body: "Forbidden" };
  }

  await client.send(new DeleteItemCommand({
    TableName: "redirects",
    Key: { slug: { S: body.slug } }
  }));

  return { statusCode: 200, headers: cors, body: "deleted" };
}


// ================= ADMIN USERS =================
if (path.includes("admin/users")) {

  const res = await client.send(new ScanCommand({
    TableName: "users"
  }));

  const users = (res.Items || []).map(i => ({
    username: i.username?.S || "unknown",
    role: i.role?.S || "user",
    banned: i.banned?.BOOL ?? false,
    requests: Number(i.requests?.N || 0)
  }));

  return { statusCode: 200, headers: cors, body: JSON.stringify({ users }) };
}


// ================= CREATE USER =================
if (path.includes("admin/create-user")) {

  const body = getBody(event);

  await client.send(new PutItemCommand({
    TableName: "users",
    Item: {
      username: { S: body.username },
      password: { S: hash(body.password) },
      role: { S: body.role || "user" },
      banned: { BOOL: false },
      createdAt: { N: String(Date.now()) }
    }
  }));

  return { statusCode: 200, headers: cors, body: "User created" };
}


// ================= ROLE CONTROL =================
if (path.includes("admin/make-admin")) {

  const body = getBody(event);

  await client.send(new UpdateItemCommand({
    TableName: "users",
    Key: { username: { S: body.username } },
    UpdateExpression: "SET #r = :r",
    ExpressionAttributeNames: { "#r": "role" },
    ExpressionAttributeValues: { ":r": { S: "admin" } }
  }));

  return { statusCode: 200, headers: cors, body: "ok" };
}

if (path.includes("admin/remove-admin")) {

  const body = getBody(event);

  await client.send(new UpdateItemCommand({
    TableName: "users",
    Key: { username: { S: body.username } },
    UpdateExpression: "SET #r = :r",
    ExpressionAttributeNames: { "#r": "role" },
    ExpressionAttributeValues: { ":r": { S: "user" } }
  }));

  return { statusCode: 200, headers: cors, body: "ok" };
}


// ================= EMAIL LOGS =================
if (path.includes("admin/email-logs")) {

  const res = await client.send(new ScanCommand({
    TableName: "email_logs"
  }));

  const logs = (res.Items || []).map(i => ({
    type: i.type?.S,
    time: Number(i.time?.N || 0)
  }));

  return {
    statusCode: 200,
    headers: cors,
    body: JSON.stringify({ logs })
  };
}


// ================= AUDIT LOGS =================
if (path.includes("admin/audit") && method === "POST") {

  const body = getBody(event);

  await client.send(new PutItemCommand({
    TableName: "audit_logs",
    Item: {
      id: { S: crypto.randomUUID() },
      action: { S: body.action },
      target: { S: body.target },
      time: { N: String(body.time) },
      admin: { S: body.admin }
    }
  }));

  return { statusCode: 200, headers: cors, body: "ok" };
}

if (path.includes("admin/audit") && method === "GET") {

  const res = await client.send(new ScanCommand({
    TableName: "audit_logs"
  }));

  const logs = (res.Items || []).map(i => ({
    action: i.action.S,
    target: i.target.S,
    time: Number(i.time.N)
  }));

  return {
    statusCode: 200,
    headers: cors,
    body: JSON.stringify({ logs })
  };
}

    // ================= ADMIN CONTROL =================
    if (path.includes("admin/ban")) {
      const body = getBody(event);

      await client.send(new UpdateItemCommand({
        TableName: "users",
        Key: { username: { S: body.username } },
        UpdateExpression: "SET banned = :b",
        ExpressionAttributeValues: { ":b": { BOOL: true } }
      }));

      return { statusCode: 200, headers: cors, body: "banned" };
    }

    if (path.includes("admin/unban")) {
      const body = getBody(event);

      await client.send(new UpdateItemCommand({
        TableName: "users",
        Key: { username: { S: body.username } },
        UpdateExpression: "SET banned = :b",
        ExpressionAttributeValues: { ":b": { BOOL: false } }
      }));

      return { statusCode: 200, headers: cors, body: "unbanned" };
    }

    if (path.includes("admin/geo")) {
      const body = getBody(event);

      await client.send(new UpdateItemCommand({
        TableName: "users",
        Key: { username: { S: body.username } },
        UpdateExpression: "SET geoTracking = :g",
        ExpressionAttributeValues: { ":g": { BOOL: !!body.enabled } }
      }));

      return { statusCode: 200, headers: cors, body: "geo updated" };
    }

    if (path.includes("admin/pause")) {
      const body = getBody(event);

      await client.send(new UpdateItemCommand({
        TableName: "redirects",
        Key: { slug: { S: body.slug } },
        UpdateExpression: "SET paused = :p",
        ExpressionAttributeValues: { ":p": { BOOL: true } }
      }));

      return { statusCode: 200, headers: cors, body: "paused" };
    }

    if (path.includes("admin/resume")) {
      const body = getBody(event);

      await client.send(new UpdateItemCommand({
        TableName: "redirects",
        Key: { slug: { S: body.slug } },
        UpdateExpression: "SET paused = :p",
        ExpressionAttributeValues: { ":p": { BOOL: false } }
      }));

      return { statusCode: 200, headers: cors, body: "resumed" };
    }

    // 🔥 BLOCK IP
    if (path.includes("admin/block-ip")) {
      const body = getBody(event);

      await client.send(new PutItemCommand({
        TableName: "blocked_ips",
        Item: { ip: { S: body.ip } }
      }));

      return { statusCode: 200, headers: cors, body: "IP blocked" };
    }

    // 🔥 UNBLOCK IP
    if (path.includes("admin/unblock-ip")) {
      const body = getBody(event);

      await client.send(new DeleteItemCommand({
        TableName: "blocked_ips",
        Key: { ip: { S: body.ip } }
      }));

      return { statusCode: 200, headers: cors, body: "IP unblocked" };
    }

    return { statusCode: 404, headers: cors, body: "Route not found" };

  } catch (err) {
    console.error(err);
    return { statusCode: 500, headers: cors, body: err.message };
  }
};