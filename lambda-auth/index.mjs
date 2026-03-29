import {
  DynamoDBClient,
  PutItemCommand,
  ScanCommand,
  DeleteItemCommand,
  UpdateItemCommand,
  GetItemCommand
} from "@aws-sdk/client-dynamodb";

import crypto from "crypto";

// ================= CLIENTS =================
const client = new DynamoDBClient({ region: "us-east-2" });
const BASE_URL = "https://suvegwrmzl.execute-api.us-east-2.amazonaws.com";
const RECAPTCHA_SECRET = "6LfBaZwsAAAAALGh_1Ld0rYE-3ws60BA9Wvt6pRO";


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

    if(!token) return false;
  
    const res = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `secret=${RECAPTCHA_SECRET}&response=${token}`
    });
  
    const data = await res.json();
  
    console.log("CAPTCHA RESULT:", data);
  
    return data.success === true;
  }
// ================= HANDLER =================
export const handler = async (event) => {

  const method = event.requestContext?.http?.method || "GET";
  let path = event.requestContext?.http?.path || "/";
  path = path.toLowerCase();

  if (method === "OPTIONS") {
    return { statusCode: 200, headers: cors };
  }

  try {

    
    if (method === "POST" && path.includes("signup")) {

        const body = getBody(event);
        const username = body.username?.trim().toLowerCase();
        const password = body.password;
      
        if (!username || !password || !body.captcha) {
          return { statusCode: 400, headers: cors, body: "Invalid input" };
        }
      
        // 🔥 CAPTCHA CHECK
        const validCaptcha = await verifyCaptcha(body.captcha);
      
        if (!validCaptcha) {
          return { statusCode: 403, headers: cors, body: "Captcha failed" };
        }
      
        const existing = await client.send(new GetItemCommand({
          TableName: "users",
          Key: { username: { S: username } }
        }));
      
        if (existing.Item) {
          return { statusCode: 400, headers: cors, body: "User already exists" };
        }
      
        await client.send(new PutItemCommand({
          TableName: "users",
          Item: {
            username: { S: username },
            password: { S: hash(password) },
            role: { S: "user" },
            banned: { BOOL: false }
          }
        }));
      
        return {
          statusCode: 200,
          headers: cors,
          body: "Account created successfully"
        };
      }
      if (method === "POST" && path.includes("login")) {

        const body = getBody(event);
        const username = body.username?.trim().toLowerCase();
        const password = body.password;
      
        if (!username || !password || !body.captcha) {
          return { statusCode: 400, headers: cors, body: "Missing credentials" };
        }
      
        // 🔥 CAPTCHA CHECK
        const validCaptcha = await verifyCaptcha(body.captcha);
      
        if (!validCaptcha) {
          return { statusCode: 403, headers: cors, body: "Captcha failed" };
        }
      
        const res = await client.send(new GetItemCommand({
          TableName: "users",
          Key: { username: { S: username } }
        }));
      
        if (!res.Item || res.Item.password?.S !== hash(password)) {
          return { statusCode: 401, headers: cors, body: "Invalid credentials" };
        }
      
        if (res.Item.banned?.BOOL) {
          return { statusCode: 403, headers: cors, body: "Account blocked" };
        }
      
        return {
          statusCode: 200,
          headers: cors,
          body: JSON.stringify({
            token: generateToken(username),
            role: res.Item.role?.S || "user"
          })
        };
      }
// ================= RESET PASSWORD =================
if (method === "POST" && path.includes("reset")) {

  const body = getBody(event);

  if(!body.token || !body.password){
    return { statusCode: 400, headers: cors, body: "Missing data" };
  }

  // 🔥 find user by resetToken
  const res = await client.send(new ScanCommand({
    TableName: "users"
  }));

  const user = (res.Items || []).find(u => u.resetToken?.S === body.token);

  if(!user){
    return { statusCode: 400, headers: cors, body: "Invalid token" };
  }

  // 🔥 update password
  await client.send(new UpdateItemCommand({
    TableName: "users",
    Key: { username: { S: user.username.S } },
    UpdateExpression: "SET password = :p REMOVE resetToken",
    ExpressionAttributeValues: {
      ":p": { S: hash(body.password) }
    }
  }));

  return {
    statusCode: 200,
    headers: cors,
    body: "Password updated"
  };
}

// ================= REDIRECT (FINAL COMPLETE + HARDENED) =================
if (
  method === "GET" &&
  !path.includes("create") &&
  !path.includes("list") &&
  !path.includes("admin")
) {

  const parts = path.split("/").filter(Boolean);
  const slugRaw = parts.length ? parts.pop() : null;

  // 🔥 normalize slug (IMPORTANT)
  const slug = (slugRaw || "").trim();

  const headers = event.headers || {};
  const ip = getIP(event);

  console.log("IP DETECTED:", ip);
  console.log("SLUG:", slug);

  if (!slug) {
    return { statusCode: 400, headers: cors, body: "Invalid slug" };
  }

  // ================= IP INTELLIGENCE =================
  const vpn = typeof isVPN === "function" ? isVPN(ip, headers) : false;
  const bot = typeof isBot === "function" ? isBot(headers) : false;
  const risk = typeof scoreIP === "function" ? scoreIP(ip, headers) : 0;

  // ================= BLOCKED IP CHECK =================
  try {
    const blocked = await client.send(new GetItemCommand({
      TableName: "blocked_ips",
      Key: { ip: { S: String(ip || "unknown") } }
    }));

    if (blocked.Item) {
      return { statusCode: 403, headers: cors, body: "IP blocked" };
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
    return { statusCode: 404, headers: cors, body: "Not found" };
  }

  // ================= PAUSE CHECK =================
  if (res.Item.paused?.BOOL) {
    return { statusCode: 403, headers: cors, body: "Link paused" };
  }

  // ================= EXPIRE CHECK =================
  if (res.Item.expire?.N) {
    const expireTime = Number(res.Item.expire.N);

    if (Date.now() > expireTime) {
      return { statusCode: 410, headers: cors, body: "Link expired" };
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

  // ================= STORE CLICK (FINAL SAFE WRITE) =================
  try {

    const timestamp = Date.now();

    await client.send(new PutItemCommand({
      TableName: "clicks",
      Item: {
        // 🔥 REQUIRED UNIQUE KEY (CRITICAL)
        id: { S: `${slug}#${timestamp}#${Math.random().toString(36).slice(2,6)}` },

        slug: { S: slug },
        time: { N: String(timestamp) },
        ip: { S: String(ip || "unknown") },

        vpn: { BOOL: vpn },
        bot: { BOOL: bot },
        risk: { N: String(risk) },
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
  const res = await client.send(new ScanCommand({
    TableName: "redirects"
  }));

  const items = (res.Items || []).map(i => ({
    slug: i.slug?.S || "",
    url: i.url?.S || "",
    clicks: Number(i.clicks?.N || 0),
    paused: i.paused?.BOOL || false,
    user: i.user?.S || "",

    // ✅ EXPIRE FIX (ONLY ADDITION)
    expire: i.expire?.N ? Number(i.expire.N) : null
  }));

  return {
    statusCode: 200,
    headers: cors,
    body: JSON.stringify({ items })
  };
}
// ================= HISTORY (FINAL WORKING + SAFE) =================
if (method === "GET" && path.includes("history")) {

  const rawSlug = event.queryStringParameters?.slug || "";
  const slug = rawSlug.trim().toLowerCase();

  if(!slug){
    return { statusCode: 400, headers: cors, body: "Missing slug" };
  }

  let allItems = [];
  let lastKey;

  // 🔥 PAGINATION SAFE
  do {
    const res = await client.send(new ScanCommand({
      TableName: "clicks",
      ExclusiveStartKey: lastKey
    }));

    if(res.Items) allItems.push(...res.Items);
    lastKey = res.LastEvaluatedKey;

  } while (lastKey);

  console.log("ALL CLICK ITEMS:", allItems.length);
  console.log("REQUEST SLUG:", slug);

  // ================= MATCH (FIXED) =================
  let history = allItems
    .filter(i => {
      const dbSlug = (i.slug?.S || "").toLowerCase().trim();

      // 🔥 FLEXIBLE MATCH (IMPORTANT FIX)
      return dbSlug === slug || dbSlug.includes(slug);
    })
    .map(i => ({
      time: Number(i.time?.N || Date.now()),
      ip: i.ip?.S || "unknown",
      vpn: i.vpn?.BOOL || false,
      bot: i.bot?.BOOL || false,
      risk: Number(i.risk?.N || 0)
    }))
    .sort((a,b)=>b.time - a.time);

  console.log("MATCHED HISTORY:", history.length);

  // ================= FALLBACK (ONLY IF REALLY EMPTY) =================
  if(history.length === 0){
    console.warn("No matching history found for slug:", slug);

    return {
      statusCode: 200,
      headers: cors,
      body: JSON.stringify({ history: [] })
    };
  }

  return {
    statusCode: 200,
    headers: cors,
    body: JSON.stringify({ history })
  };
}
    // ================= DELETE =================
    if (method === "POST" && path.includes("delete")) {
      const body = getBody(event);

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
        geoTracking: i.geoTracking?.BOOL ?? true,
        apiKey: i.apiKey?.S || "",
        requests: Number(i.requests?.N || 0)
      }));

      return { statusCode: 200, headers: cors, body: JSON.stringify({ users }) };
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