/**
 * incident-bridge — SkillHub rollback demo (FireHydrant heartbeat edition)
 * --------------------------------------------------------------
 * DEPLOY THIS SEPARATELY from SkillHub, on an ALWAYS-ON host
 * (Render / Railway / Fly — NOT serverless: it runs a setInterval
 * heartbeat). It must stay up while SkillHub is broken, or both the
 * heartbeat logic and the rollback button die with the app.
 *
 * Detection = FireHydrant Signals heartbeat (push / dead-man's-switch):
 *   1) Every 30s the bridge pings SkillHub /health.
 *   2) If healthy (200) -> forward a heartbeat ping to FireHydrant.
 *   3) If SkillHub is down -> NO ping is sent -> FireHydrant's heartbeat
 *      window lapses -> FireHydrant opens an alert/incident.
 *   4) FireHydrant's Webhook Alert Target POSTs to /firehydrant/webhook
 *      -> bridge posts a Slack message with a chart + "Roll back" button.
 *   5) Click -> /slack/interactions verifies -> Vercel rollback -> recovered.
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
  SLACK_BOT_TOKEN,
  SLACK_SIGNING_SECRET,
  SLACK_CHANNEL_ID,
  VERCEL_TOKEN,
  VERCEL_PROJECT_ID,
  VERCEL_TEAM_ID,
  GOOD_DEPLOYMENT_ID,         // optional but RECOMMENDED for demos: pin the rollback target
  PORT = 3000,
} = process.env;

const vercelAuth = { Authorization: `Bearer ${VERCEL_TOKEN}` };
const teamQuery = VERCEL_TEAM_ID ? `?teamId=${VERCEL_TEAM_ID}` : "";

/* ---------- charts (static PNG; render reliably in Slack) ---------- */
function chartUrl(data, color) {
  const cfg = {
    type: "line",
    data: { labels: ["-4m", "-3m", "-2m", "-1m", "now"],
      datasets: [{ label: "5xx errors/min", data, borderColor: color, fill: false }] },
    options: { scales: { y: { beginAtZero: true } } },
  };
  return `https://quickchart.io/chart?w=500&h=250&c=${encodeURIComponent(JSON.stringify(cfg))}`;
}
const INCIDENT_CHART = chartUrl([0, 0, 1, 6, 11], "rgb(220,38,38)");
const RECOVERY_CHART = chartUrl([11, 6, 1, 0, 0], "rgb(22,163,74)");

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

/* ---------- 2) FireHydrant Webhook Alert Target -> actionable Slack message ---------- */
function verifyFireHydrant(rawBody, signature) {
  if (!FH_WEBHOOK_SIGNING_KEY) return true; // skip if no signing key configured
  const expected = crypto.createHmac("sha256", FH_WEBHOOK_SIGNING_KEY).update(rawBody).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature || "")); }
  catch { return false; }
}

app.post("/firehydrant/webhook", async (req, res) => {
  const raw = req.body.toString("utf8");
  // Confirm the exact header name in FireHydrant > Webhook Logs (often "Firehydrant-Signature").
  const sig = req.headers["firehydrant-signature"] || req.headers["x-firehydrant-signature"];
  if (!verifyFireHydrant(raw, sig)) return res.status(401).send("bad signature");
  res.sendStatus(200); // ack fast

  let alertId = "unknown", summary = "SkillHub heartbeat missed — site is not responding";
  try {
    const p = JSON.parse(raw);
    alertId = p?.id || p?.data?.alert?.id || "unknown";
    summary = p?.data?.alert?.summary || p?.summary || summary;
  } catch {}
  await postSlackIncident(alertId, summary);
});

async function postSlackIncident(alertId, summary) {
  await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${SLACK_BOT_TOKEN}` },
    body: JSON.stringify({
      channel: SLACK_CHANNEL_ID,
      text: "SkillHub production incident",
      blocks: [
        { type: "header", text: { type: "plain_text", text: "🚨 SkillHub production incident" } },
        { type: "section", text: { type: "mrkdwn", text: `*${summary}*\nFireHydrant heartbeat stopped — likely a bad production deploy.` } },
        { type: "image", image_url: INCIDENT_CHART, alt_text: "5xx error rate spiking" },
        { type: "actions", elements: [{
          type: "button", style: "danger", action_id: "rollback_prod",
          text: { type: "plain_text", text: "Roll back production" }, value: alertId,
          confirm: {
            title: { type: "plain_text", text: "Roll back?" },
            text: { type: "mrkdwn", text: "Promote the previous good deployment to production." },
            confirm: { type: "plain_text", text: "Roll back" }, deny: { type: "plain_text", text: "Cancel" },
          },
        }] },
      ],
    }),
  });
}

/* ---------- 3) Slack button click -> verify -> Vercel rollback -> update message ---------- */
function verifySlack(rawBody, ts, sig) {
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false; // replay guard
  const base = `v0:${ts}:${rawBody}`;
  const expected = "v0=" + crypto.createHmac("sha256", SLACK_SIGNING_SECRET).update(base).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig || "")); }
  catch { return false; }
}

app.post("/slack/interactions", async (req, res) => {
  const raw = req.body.toString("utf8");
  if (!verifySlack(raw, req.headers["x-slack-request-timestamp"], req.headers["x-slack-signature"]))
    return res.status(401).send("bad signature");

  const payload = JSON.parse(new URLSearchParams(raw).get("payload"));
  res.sendStatus(200); // ack within 3s
  if (payload.actions?.[0]?.action_id !== "rollback_prod") return;

  const responseUrl = payload.response_url;
  await replaceSlack(responseUrl, "⏳ Rolling back production…", []);
  try {
    const { ok, target } = await rollbackVercel();
    await replaceSlack(
      responseUrl,
      ok ? `✅ Rolled back to \`${target}\`. Service restored.` : "❌ Rollback API call failed — check bridge logs.",
      ok ? [{ type: "image", image_url: RECOVERY_CHART, alt_text: "error rate recovering" }] : []
    );
  } catch (e) {
    await replaceSlack(responseUrl, `❌ Rollback errored: ${e.message}`, []);
  }
});

async function replaceSlack(responseUrl, text, extraBlocks) {
  await fetch(responseUrl, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ replace_original: true, text,
      blocks: [{ type: "section", text: { type: "mrkdwn", text } }, ...extraBlocks] }),
  });
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
app.get("/", (_req, res) => res.send("incident-bridge up (FireHydrant heartbeat edition)"));
app.listen(PORT, () => {
  console.log(`incident-bridge on :${PORT}`);
  setInterval(heartbeat, 30_000); // send a heartbeat every 30s while SkillHub is healthy
  heartbeat();
});
