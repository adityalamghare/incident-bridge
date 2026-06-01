/**
 * incident-bridge — SkillHub rollback demo (FireHydrant Command Extension edition)
 * --------------------------------------------------------------
 * DEPLOY THIS SEPARATELY from SkillHub, on an ALWAYS-ON host
 * (Render / Railway / Fly — NOT serverless: it runs a setInterval
 * heartbeat). It must stay up while SkillHub is broken, or both the
 * heartbeat logic and the rollback command die with the app.
 *
 * Detection = FireHydrant Signals heartbeat (push / dead-man's-switch):
 *   1) Every 30s the bridge pings SkillHub /health.
 *   2) If healthy (200) -> forward a heartbeat ping to FireHydrant.
 *   3) If SkillHub is down -> NO ping is sent -> FireHydrant's heartbeat
 *      window lapses -> FireHydrant opens an alert/incident.
 *   4) FireHydrant's Webhook Alert Target POSTs to /firehydrant/webhook
 *      (kept for logging / future use).
 *
 * Remediation = FireHydrant Command Extension:
 *   - A responder runs `/fh rollback` in the incident's Slack channel.
 *   - FireHydrant POSTs to /rollback (this service).
 *   - The bridge verifies, rolls back Vercel, and replies to FireHydrant's
 *     callback URL with a timeline note ("new_note").
 *
 * Node 18+ (global fetch). `npm i express`
 */
const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.raw({ type: "*/*", limit: "1mb" })); // raw body for signature checks

const {
  SKILLHUB_HEALTH_URL,        // e.g. https://skillhub-rosy.vercel.app/health (or /)
  FH_HEARTBEAT_URL,           // the heartbeat ping URL from FireHydrant Signals
  FH_WEBHOOK_SIGNING_KEY,     // signing key set on the FireHydrant Webhook Alert Target
  FH_COMMAND_SIGNING_SECRET,  // signing secret set on the FireHydrant Command Extension
  VERCEL_TOKEN,
  VERCEL_PROJECT_ID,
  VERCEL_TEAM_ID,
  GOOD_DEPLOYMENT_ID,         // optional but RECOMMENDED for demos: pin the rollback target
  PORT = 3000,
} = process.env;

const vercelAuth = { Authorization: `Bearer ${VERCEL_TOKEN}` };
const teamQuery = VERCEL_TEAM_ID ? `?teamId=${VERCEL_TEAM_ID}` : "";

/* ---------- 1) Heartbeat: ping SkillHub, forward to FireHydrant only if healthy ---------- */
async function heartbeat() {
  try {
    const res = await fetch(SKILLHUB_HEALTH_URL, { signal: AbortSignal.timeout(8000) });
    if (res.ok) {
      // Healthy -> tell FireHydrant we're alive. (Heartbeats usually accept GET or POST;
      // confirm the method in the FireHydrant heartbeat's setup page.)
      await fetch(FH_HEARTBEAT_URL, { method: "POST" }).catch(() => {});
      console.log("heartbeat sent (healthy)");
    } else {
      console.log(`SkillHub unhealthy (${res.status}) — withholding heartbeat`);
    }
    // If unhealthy we intentionally send NOTHING. FireHydrant alerts on the silence.
  } catch {
    console.log("SkillHub unreachable — withholding heartbeat");
  }
}

/* ---------- FireHydrant signature verification (shared HMAC-SHA256 hex style) ---------- */
function verifyFireHydrantSig(rawBody, signature, secret) {
  if (!secret) return true; // skip if no signing secret configured
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature || "")); }
  catch { return false; }
}

/* ---------- 2) FireHydrant Webhook Alert Target (kept for logging / future use) ---------- */
app.post("/firehydrant/webhook", async (req, res) => {
  const raw = req.body.toString("utf8");
  // Confirm the exact header name in FireHydrant > Webhook Logs (often "Firehydrant-Signature").
  const sig = req.headers["firehydrant-signature"] || req.headers["x-firehydrant-signature"];
  if (!verifyFireHydrantSig(raw, sig, FH_WEBHOOK_SIGNING_KEY)) return res.status(401).send("bad signature");
  res.sendStatus(200); // ack fast

  let alertId = "unknown", summary = "SkillHub heartbeat missed — site is not responding";
  try {
    const p = JSON.parse(raw);
    alertId = p?.id || p?.data?.alert?.id || "unknown";
    summary = p?.data?.alert?.summary || p?.summary || summary;
  } catch {}
  console.log(`FireHydrant alert received: ${alertId} — ${summary}`);
});

/* ---------- 3) FireHydrant Command Extension: /fh rollback -> POST /rollback ---------- */
let loggedCommandPayload = false;

// FireHydrant includes a unique callback URL in the command payload so you can reply
// with timeline notes. Read it defensively from the likely locations.
function extractCallbackUrl(payload) {
  return (
    payload?.callback_url ||
    payload?.callbackUrl ||
    payload?.data?.callback_url ||
    payload?.command?.callback_url ||
    payload?.extension?.callback_url ||
    null
  );
}

app.post("/rollback", async (req, res) => {
  const raw = req.body.toString("utf8");
  // Confirm the exact header name in FireHydrant > Command Extension logs.
  const sig = req.headers["firehydrant-signature"] || req.headers["x-firehydrant-signature"];
  if (!verifyFireHydrantSig(raw, sig, FH_COMMAND_SIGNING_SECRET)) return res.status(401).send("bad signature");
  res.sendStatus(200); // ack immediately so FireHydrant doesn't time out

  let payload = {};
  try { payload = JSON.parse(raw); } catch {}

  // Log the full payload on first run so we can confirm the exact field name.
  if (!loggedCommandPayload) {
    loggedCommandPayload = true;
    console.log("FIRST /rollback payload (inspect for callback URL field name):");
    console.log(JSON.stringify(payload, null, 2));
  }

  const callbackUrl = extractCallbackUrl(payload);
  if (!callbackUrl) {
    console.log("No callback URL found in command payload — cannot reply to FireHydrant.");
  }

  try {
    const { ok, target } = await rollbackVercel();
    const body = ok
      ? `✅ Rolled back to ${target} — production restored`
      : `❌ Rollback API call failed (target ${target}) — check bridge logs`;
    await replyToFireHydrant(callbackUrl, body);
  } catch (e) {
    await replyToFireHydrant(callbackUrl, `❌ Rollback errored: ${e.message}`);
  }
});

// Post a timeline note back to FireHydrant's command callback URL.
async function replyToFireHydrant(callbackUrl, message) {
  console.log(`rollback result: ${message}`);
  if (!callbackUrl) return;
  await fetch(callbackUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      reply_type: "actions",
      actions: [{ action: "new_note", body: message }],
    }),
  }).catch((e) => console.log(`failed to post reply to FireHydrant: ${e.message}`));
}

/* ---------- Vercel rollback ---------- */
async function rollbackVercel() {
  const q = new URLSearchParams({ projectId: VERCEL_PROJECT_ID, limit: "2",
    rollbackCandidate: "true", state: "READY", target: "production" });
  if (VERCEL_TEAM_ID) q.set("teamId", VERCEL_TEAM_ID);

  const list = await fetch(`https://api.vercel.com/v6/deployments?${q}`, { headers: vercelAuth }).then(r => r.json());
  const target = GOOD_DEPLOYMENT_ID || list.deployments?.[1]?.uid; // [0] is the current/broken one
  if (!target) throw new Error("No previous production deployment found to roll back to.");

  // CLI uses /v9; /v1 is documented for rolling releases. If one 404s, swap the version.
  const rb = await fetch(`https://api.vercel.com/v9/projects/${VERCEL_PROJECT_ID}/rollback/${target}${teamQuery}`, {
    method: "POST", headers: { ...vercelAuth, "Content-Type": "application/json" }, body: "{}",
  });
  return { ok: rb.ok, target };
}

/* ---------- boot ---------- */
app.get("/", (_req, res) => res.send("incident-bridge up (FireHydrant Command Extension edition)"));
app.listen(PORT, () => {
  console.log(`incident-bridge on :${PORT}`);
  setInterval(heartbeat, 30_000); // send a heartbeat every 30s while SkillHub is healthy
  heartbeat();
});
