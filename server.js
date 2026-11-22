require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3001;
const META_APP_ID = process.env.META_APP_ID || "";
const META_APP_SECRET = process.env.META_APP_SECRET || "";
const GRAPH_VERSION = process.env.META_GRAPH_VERSION || "v21.0";
const BACKEND_URL = (process.env.BACKEND_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
const FRONTEND_URL = (process.env.FRONTEND_URL || "http://localhost:5500").replace(/\/+$/, "");
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

const ENC_KEY = crypto.createHash("sha256").update(SESSION_SECRET).digest();
const STORE_PATH = path.join(__dirname, ".fb_sessions.enc");

const FRONTEND_ORIGIN = (() => {
  try {
    return new URL(FRONTEND_URL).origin;
  } catch {
    return FRONTEND_URL;
  }
})();

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || origin === FRONTEND_ORIGIN) return callback(null, true);
      return callback(new Error("Origin không được phép truy cập API."));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "x-page-id",
      "x-upload-session-id",
      "x-start-offset"
    ]
  })
);

app.use(express.json({ limit: "2mb" }));

/* ===================== MÃ HÓA AES-256-GCM LƯU TOKEN AN TOÀN ===================== */

function encryptText(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(plainText), "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString("hex")}:${authTag.toString("hex")}:${encrypted.toString("hex")}`;
}

function decryptText(payload) {
  const [ivHex, tagHex, dataHex] = String(payload).split(":");
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(tagHex, "hex"));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, "hex")), decipher.final()]).toString("utf8");
}

const oauthStates = new Map();
let sessions = {};

function loadStore() {
  try {
    if (!fs.existsSync(STORE_PATH)) return;
    const raw = fs.readFileSync(STORE_PATH, "utf8");
    sessions = JSON.parse(decryptText(raw));
  } catch {
    sessions = {};
  }
}

function saveStore() {
  try {
    fs.writeFileSync(STORE_PATH, encryptText(JSON.stringify(sessions)), { mode: 0o600 });
  } catch (err) {
    console.error("Không thể lưu file phiên mã hóa:", err.message);
  }
}

loadStore();

/* ===================== TIỆN ÍCH META GRAPH API ===================== */

function parseMetaError(data, fallbackMsg) {
  if (data && data.error) {
    const e = data.error;
    return e.error_user_msg || e.message || fallbackMsg;
  }
  return fallbackMsg;
}

async function fetchUserPages(userAccessToken) {
  const url =
    `https://graph.facebook.com/${GRAPH_VERSION}/me/accounts` +
    `?fields=id,name,access_token,picture.type(small){url},tasks&limit=100` +
    `&access_token=${encodeURIComponent(userAccessToken)}`;

  const res = await fetch(url);
  const data = await res.json();
  if (!res.ok || data.error) {
    throw new Error(parseMetaError(data, "Không thể lấy danh sách Fanpage."));
  }

  return (data.data || []).map((page) => ({
    id: page.id,
    name: page.name,
    picture: page.picture?.data?.url || "",
    encryptedAccessToken: encryptText(page.access_token)
  }));
}

function requireSession(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  if (!token || !sessions[token]) {
    return res.status(401).json({ error: "Chưa kết nối Facebook hoặc phiên đăng nhập đã hết hạn." });
  }
  req.sessionId = token;
  req.fbSession = sessions[token];
  next();
}

function getDecryptedPageToken(session, pageId) {
  const page = (session.pages || []).find((p) => p.id === String(pageId));
  if (!page) return null;
  return {
    page,
    accessToken: decryptText(page.encryptedAccessToken)
  };
}

/* ===================== ROUTES KIỂM TRA & OAUTH FACEBOOK ===================== */

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "KAI TỒ VIDEO CUTTER - Meta Graph Backend",
    graphVersion: GRAPH_VERSION,
    configured: Boolean(META_APP_ID && META_APP_SECRET)
  });
});

app.get("/auth/facebook/login", (_req, res) => {
  if (!META_APP_ID || !META_APP_SECRET) {
    return res.status(500).send("Backend chưa cấu hình META_APP_ID và META_APP_SECRET.");
  }

  const state = crypto.randomBytes(24).toString("hex");
  oauthStates.set(state, Date.now() + 10 * 60 * 1000);

  const redirectUri = `${BACKEND_URL}/auth/facebook/callback`;
  const scopes = [
    "pages_show_list",
    "pages_read_engagement",
    "pages_manage_posts"
  ].join(",");

  const authUrl =
    `https://www.facebook.com/${GRAPH_VERSION}/dialog/oauth` +
    `?client_id=${encodeURIComponent(META_APP_ID)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&response_type=code`;

  res.redirect(authUrl);
});

app.get("/auth/facebook/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.redirect(`${FRONTEND_URL}#fb_error=${encodeURIComponent(error_description || error)}`);
  }

  const expiry = oauthStates.get(state);
  oauthStates.delete(state);
  if (!expiry || Date.now() > expiry || !code) {
    return res.redirect(`${FRONTEND_URL}#fb_error=${encodeURIComponent("Phiên xác thực OAuth không hợp lệ hoặc đã hết hạn.")}`);
  }

  try {
    const redirectUri = `${BACKEND_URL}/auth/facebook/callback`;

    const tokenRes = await fetch(
      `https://graph.facebook.com/${GRAPH_VERSION}/oauth/access_token` +
        `?client_id=${encodeURIComponent(META_APP_ID)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&client_secret=${encodeURIComponent(META_APP_SECRET)}` +
        `&code=${encodeURIComponent(code)}`
    );
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok || !tokenData.access_token) {
      throw new Error(parseMetaError(tokenData, "Không đổi được mã xác thực Facebook."));
    }

    let finalUserToken = tokenData.access_token;
    try {
      const longRes = await fetch(
        `https://graph.facebook.com/${GRAPH_VERSION}/oauth/access_token` +
          `?grant_type=fb_exchange_token` +
          `&client_id=${encodeURIComponent(META_APP_ID)}` +
          `&client_secret=${encodeURIComponent(META_APP_SECRET)}` +
          `&fb_exchange_token=${encodeURIComponent(tokenData.access_token)}`
      );
      const longData = await longRes.json();
      if (longRes.ok && longData.access_token) {
        finalUserToken = longData.access_token;
      }
    } catch (_) {}

    const meRes = await fetch(
      `https://graph.facebook.com/${GRAPH_VERSION}/me?fields=id,name&access_token=${encodeURIComponent(finalUserToken)}`
    );
    const meData = await meRes.json();
    if (!meRes.ok || meData.error) {
      throw new Error(parseMetaError(meData, "Không đọc được thông tin tài khoản Facebook."));
    }

    const pages = await fetchUserPages(finalUserToken);
    const sessionId = crypto.randomBytes(32).toString("hex");

    sessions[sessionId] = {
      user: { id: meData.id, name: meData.name },
      encryptedUserToken: encryptText(finalUserToken),
      pages,
      publishedKeys: {},
      createdAt: Date.now()
    };
    saveStore();

    return res.redirect(`${FRONTEND_URL}#fb_session=${encodeURIComponent(sessionId)}`);
  } catch (err) {
    return res.redirect(`${FRONTEND_URL}#fb_error=${encodeURIComponent(err.message)}`);
  }
});

/* ===================== ROUTES QUẢN LÝ PHIÊN & FANPAGE ===================== */

app.get("/api/facebook/session", requireSession, (req, res) => {
  res.json({
    connected: true,
    user: req.fbSession.user,
    pages: (req.fbSession.pages || []).map((p) => ({
      id: p.id,
      name: p.name,
      picture: p.picture
    }))
  });
});

app.post("/api/facebook/refresh-pages", requireSession, async (req, res) => {
  try {
    const userToken = decryptText(req.fbSession.encryptedUserToken);
    const pages = await fetchUserPages(userToken);
    req.fbSession.pages = pages;
    saveStore();
    res.json({
      pages: pages.map((p) => ({ id: p.id, name: p.name, picture: p.picture }))
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/facebook/logout", requireSession, (req, res) => {
  delete sessions[req.sessionId];
  saveStore();
  res.json({ ok: true });
});

/* ===================== ROUTES ĐĂNG VIDEO RESUMABLE (3 PHA) ===================== */

app.post("/api/facebook/upload/start", requireSession, async (req, res) => {
  try {
    const { pageId, fileSize, idempotencyKey } = req.body || {};
    if (!pageId || !fileSize || Number(fileSize) <= 0) {
      return res.status(400).json({ error: "Thiếu pageId hoặc fileSize hợp lệ." });
    }

    if (idempotencyKey && req.fbSession.publishedKeys?.[idempotencyKey]) {
      const prev = req.fbSession.publishedKeys[idempotencyKey];
      return res.status(409).json({
        error: "Video tập này đã được đăng lên Fanpage trước đó.",
        alreadyPublished: true,
        videoId: prev.videoId,
        permalinkUrl: prev.permalinkUrl
      });
    }

    const found = getDecryptedPageToken(req.fbSession, pageId);
    if (!found) {
      return res.status(403).json({ error: "Bạn không có quyền đăng lên Fanpage này." });
    }

    const form = new FormData();
    form.append("access_token", found.accessToken);
    form.append("upload_phase", "start");
    form.append("file_size", String(fileSize));

    const fbRes = await fetch(`https://graph-video.facebook.com/${GRAPH_VERSION}/${pageId}/videos`, {
      method: "POST",
      body: form
    });
    const data = await fbRes.json();

    if (!fbRes.ok || data.error || !data.upload_session_id) {
      return res.status(400).json({ error: parseMetaError(data, "Meta từ chối khởi tạo phiên tải video.") });
    }

    res.json({
      upload_session_id: data.upload_session_id,
      video_id: data.video_id,
      start_offset: Number(data.start_offset),
      end_offset: Number(data.end_offset)
    });
  } catch (err) {
    res.status(500).json({ error: `Lỗi khởi tạo tải lên: ${err.message}` });
  }
});

app.post(
  "/api/facebook/upload/transfer",
  requireSession,
  express.raw({ type: "application/octet-stream", limit: "100mb" }),
  async (req, res) => {
    try {
      const pageId = req.headers["x-page-id"];
      const uploadSessionId = req.headers["x-upload-session-id"];
      const startOffset = req.headers["x-start-offset"];

      if (!pageId || !uploadSessionId || startOffset === undefined || !req.body || !req.body.length) {
        return res.status(400).json({ error: "Thiếu dữ liệu mảnh video cần tải lên." });
      }

      const found = getDecryptedPageToken(req.fbSession, pageId);
      if (!found) {
        return res.status(403).json({ error: "Không tìm thấy quyền Fanpage." });
      }

      const form = new FormData();
      form.append("access_token", found.accessToken);
      form.append("upload_phase", "transfer");
      form.append("upload_session_id", String(uploadSessionId));
      form.append("start_offset", String(startOffset));
      form.append("video_file_chunk", new Blob([req.body], { type: "video/mp4" }), "chunk.mp4");

      const fbRes = await fetch(`https://graph-video.facebook.com/${GRAPH_VERSION}/${pageId}/videos`, {
        method: "POST",
        body: form
      });
      const data = await fbRes.json();

      if (!fbRes.ok || data.error) {
        return res.status(400).json({ error: parseMetaError(data, "Tải mảnh video lên Facebook thất bại.") });
      }

      res.json({
        start_offset: Number(data.start_offset),
        end_offset: Number(data.end_offset)
      });
    } catch (err) {
      res.status(500).json({ error: `Lỗi truyền mảnh video: ${err.message}` });
    }
  }
);

app.post("/api/facebook/upload/finish", requireSession, async (req, res) => {
  try {
    const {
      pageId,
      uploadSessionId,
      videoId,
      title,
      description,
      publishMode,
      scheduledPublishTime,
      idempotencyKey
    } = req.body || {};

    if (!pageId || !uploadSessionId) {
      return res.status(400).json({ error: "Thiếu thông tin hoàn tất tải video." });
    }

    const found = getDecryptedPageToken(req.fbSession, pageId);
    if (!found) {
      return res.status(403).json({ error: "Không tìm thấy quyền Fanpage." });
    }

    const form = new FormData();
    form.append("access_token", found.accessToken);
    form.append("upload_phase", "finish");
    form.append("upload_session_id", String(uploadSessionId));
    if (title) form.append("title", String(title));
    if (description) form.append("description", String(description));

    if (publishMode === "schedule") {
      const unixTs = Number(scheduledPublishTime);
      const nowSec = Math.floor(Date.now() / 1000);
      if (!Number.isFinite(unixTs) || unixTs < nowSec + 600 || unixTs > nowSec + 180 * 86400) {
        return res.status(400).json({
          error: "Thời gian hẹn lịch của Facebook phải cách hiện tại từ 10 phút đến tối đa 6 tháng."
        });
      }
      form.append("published", "false");
      form.append("scheduled_publish_time", String(Math.floor(unixTs)));
    } else {
      form.append("published", "true");
    }

    const fbRes = await fetch(`https://graph-video.facebook.com/${GRAPH_VERSION}/${pageId}/videos`, {
      method: "POST",
      body: form
    });
    const data = await fbRes.json();

    if (!fbRes.ok || data.error || data.success !== true) {
      return res.status(400).json({ error: parseMetaError(data, "Facebook chưa xác nhận hoàn tất đăng video.") });
    }

    let permalinkUrl = `https://www.facebook.com/${pageId}/videos/${videoId}/`;
    if (videoId) {
      try {
        const infoRes = await fetch(
          `https://graph.facebook.com/${GRAPH_VERSION}/${videoId}?fields=permalink_url&access_token=${encodeURIComponent(found.accessToken)}`
        );
        const infoData = await infoRes.json();
        if (infoRes.ok && infoData.permalink_url) {
          permalinkUrl = infoData.permalink_url.startsWith("http")
            ? infoData.permalink_url
            : `https://www.facebook.com${infoData.permalink_url}`;
        }
      } catch (_) {}
    }

    if (idempotencyKey) {
      req.fbSession.publishedKeys = req.fbSession.publishedKeys || {};
      req.fbSession.publishedKeys[idempotencyKey] = {
        videoId,
        permalinkUrl,
        publishedAt: Date.now()
      };
      saveStore();
    }

    res.json({
      success: true,
      videoId,
      permalinkUrl,
      scheduled: publishMode === "schedule"
    });
  } catch (err) {
    res.status(500).json({ error: `Lỗi hoàn tất đăng bài: ${err.message}` });
  }
});

app.listen(PORT, () => {
  console.log(`[KAI TỒ FB Backend] Đang chạy tại cổng ${PORT} (${BACKEND_URL})`);
});
