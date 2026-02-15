import type { PatchResult, ScanResult } from "../types";

export interface NotificationPayload {
  title: string;
  summary: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  patches_verified: number;
  patches_total: number;
  pr_url?: string;
  scan_target: string;
  scan_mode: string;
}

function buildPayload(
  scanResult: ScanResult,
  patchResults: PatchResult[],
  prUrl?: string
): NotificationPayload {
  const critical = scanResult.findings.filter((f) => f.severity === "CRITICAL").length;
  const high = scanResult.findings.filter((f) => f.severity === "HIGH").length;
  const verified = patchResults.filter((r) => r.status === "patched_and_verified").length;

  return {
    title: `Hydra Security Scan: ${scanResult.findings.length} finding${scanResult.findings.length === 1 ? "" : "s"}`,
    summary: `${critical} critical, ${high} high | ${verified}/${patchResults.length} patches verified`,
    findings_count: scanResult.findings.length,
    critical_count: critical,
    high_count: high,
    patches_verified: verified,
    patches_total: patchResults.length,
    pr_url: prUrl,
    scan_target: scanResult.target.root_path,
    scan_mode: scanResult.target.mode
  };
}

function toSlackBlocks(payload: NotificationPayload): object {
  const blocks: object[] = [
    {
      type: "header",
      text: { type: "plain_text", text: payload.title }
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Target:*\n\`${payload.scan_target}\`` },
        { type: "mrkdwn", text: `*Mode:*\n${payload.scan_mode}` },
        { type: "mrkdwn", text: `*Critical:* ${payload.critical_count}` },
        { type: "mrkdwn", text: `*High:* ${payload.high_count}` },
        { type: "mrkdwn", text: `*Patches:* ${payload.patches_verified}/${payload.patches_total} verified` }
      ]
    }
  ];

  if (payload.pr_url) {
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `<${payload.pr_url}|View Pull Request>` }
    });
  }

  return { blocks };
}

function toDiscordEmbed(payload: NotificationPayload): object {
  const color = payload.critical_count > 0 ? 0xff0000 : payload.high_count > 0 ? 0xff8c00 : 0x00cc00;

  const embed: Record<string, unknown> = {
    title: payload.title,
    description: payload.summary,
    color,
    fields: [
      { name: "Target", value: `\`${payload.scan_target}\``, inline: true },
      { name: "Mode", value: payload.scan_mode, inline: true },
      { name: "Patches", value: `${payload.patches_verified}/${payload.patches_total} verified`, inline: true }
    ]
  };

  if (payload.pr_url) {
    embed.url = payload.pr_url;
  }

  return { embeds: [embed] };
}

async function postWebhook(url: string, body: object): Promise<void> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Webhook failed (${response.status}): ${text}`);
  }
}

export async function notifySlack(
  webhookUrl: string,
  scanResult: ScanResult,
  patchResults: PatchResult[] = [],
  prUrl?: string
): Promise<void> {
  const payload = buildPayload(scanResult, patchResults, prUrl);
  await postWebhook(webhookUrl, toSlackBlocks(payload));
}

export async function notifyDiscord(
  webhookUrl: string,
  scanResult: ScanResult,
  patchResults: PatchResult[] = [],
  prUrl?: string
): Promise<void> {
  const payload = buildPayload(scanResult, patchResults, prUrl);
  await postWebhook(webhookUrl, toDiscordEmbed(payload));
}

export async function notifyAll(
  scanResult: ScanResult,
  patchResults: PatchResult[] = [],
  prUrl?: string
): Promise<void> {
  const slackUrl = process.env.HYDRA_SLACK_WEBHOOK_URL;
  const discordUrl = process.env.HYDRA_DISCORD_WEBHOOK_URL;

  const tasks: Promise<void>[] = [];

  if (slackUrl) {
    tasks.push(notifySlack(slackUrl, scanResult, patchResults, prUrl));
  }
  if (discordUrl) {
    tasks.push(notifyDiscord(discordUrl, scanResult, patchResults, prUrl));
  }

  if (tasks.length > 0) {
    await Promise.allSettled(tasks);
  }
}
