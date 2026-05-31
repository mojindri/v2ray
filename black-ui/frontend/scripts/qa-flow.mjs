import { spawn } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { chromium } from "playwright";

const repoRoot = new URL("../../..", import.meta.url).pathname;
const workDir = "/tmp/black-ui-qa-flow";
const uiData = `${workDir}/ui-data`;
const bwConfig = `${workDir}/blackwire.json`;
const uiBase = "http://127.0.0.1:18094";
const grpcAddress = "127.0.0.1:26294";
const processes = [];

async function main() {
  await rm(workDir, { recursive: true, force: true });
  await mkdir(uiData, { recursive: true });
  await writeFile(
    bwConfig,
    JSON.stringify(
      {
        api: { listen: grpcAddress },
        log: { level: "info", json: false },
        inbounds: [{ tag: "seed-socks", listen: "127.0.0.1", port: 26295, protocol: "socks" }],
        outbounds: [{ tag: "freedom", protocol: "freedom", settings: {} }],
        routing: { rules: [{ outboundTag: "freedom" }] }
      },
      null,
      2
    )
  );

  await run("cargo", ["run", "-q", "-p", "blackwire", "--", "test", "-c", bwConfig]);
  processes.push(spawn("cargo", ["run", "-q", "-p", "blackwire", "--", "run", "-c", bwConfig], { cwd: repoRoot }));
  await waitForPort(26294);
  processes.push(
    spawn("cargo", ["run", "-q", "-p", "black-ui-server"], {
      cwd: repoRoot,
      env: { ...process.env, BLACK_UI_DATA_DIR: uiData, BLACK_UI_LISTEN: "127.0.0.1:18094" }
    })
  );
  await waitForHttp(`${uiBase}/api/status`);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 980 },
    permissions: ["clipboard-read", "clipboard-write"],
    origin: uiBase
  });
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  const consoleMessages = [];
  page.on("console", (msg) => {
    if (["error", "warning"].includes(msg.type())) consoleMessages.push(`${msg.type()}: ${msg.text()}`);
  });
  page.on("pageerror", (err) => consoleMessages.push(`pageerror: ${err.message}`));

  await page.goto(uiBase, { waitUntil: "networkidle" });
  await page.getByRole("heading", { name: "Create admin", exact: true }).waitFor();
  await page.getByLabel("Username", { exact: true }).fill("admin");
  await page.getByLabel("Password", { exact: true }).fill("password123");
  await page.getByRole("button", { name: "Create and enter", exact: true }).click();
  await page.getByRole("heading", { name: "Users", exact: true }).waitFor();

  await nav(page, "Settings");
  await page.getByLabel("Config path", { exact: true }).fill(`${uiData}/config.json`);
  await page.getByLabel("gRPC address", { exact: true }).fill(grpcAddress);
  await page.getByLabel("Public base URL", { exact: true }).fill(uiBase);
  await page.getByLabel("Subscription host", { exact: true }).fill("127.0.0.1");
  await page.getByRole("button", { name: "Save Settings", exact: true }).click();
  await strip(page, /Settings saved/);

  await addInbound(page, "qa-main", "26320");
  await addUser(page, "qa@example.com", "qa-main :26320");
  await page.getByRole("button", { name: "qa@example.com", exact: true }).click();
  await page.locator(".drawer").getByRole("button", { name: "Copy subscription URL", exact: true }).click();
  await page.getByText("Copied", { exact: true }).waitFor();
  await page.locator(".drawer").getByRole("button", { name: "Rotate UUID", exact: true }).click();
  await page.locator(".drawer").getByRole("button", { name: "Rotate token", exact: true }).click();
  await page.locator(".drawer").getByRole("button", { name: "Close", exact: true }).click();

  await nav(page, "Inbounds");
  await page.getByRole("button", { name: /qa-main/ }).click();
  if (await page.getByRole("button", { name: "Delete", exact: true }).isEnabled()) {
    throw new Error("last inbound delete button should be disabled");
  }
  await page.getByText("Create another inbound before deleting this one.").waitFor();
  await addInbound(page, "qa-delete", "26321");
  await page.getByRole("button", { name: /qa-delete/ }).click();
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await page.waitForFunction(() => !document.body.innerText.includes("qa-delete"));

  await nav(page, "Config");
  await page.getByRole("button", { name: "Validate", exact: true }).click();
  await strip(page, /Config valid/);
  await page.getByRole("button", { name: "Apply", exact: true }).click();
  await strip(page, /synchronized|saved/);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload({ waitUntil: "networkidle" });
  await page.getByRole("heading", { name: "Users", exact: true }).waitFor();
  await nav(page, "Settings");
  await page.getByRole("heading", { name: "Settings", exact: true }).waitFor();

  await browser.close();
  const relevantConsole = consoleMessages.filter((message) => !message.includes("401"));
  if (relevantConsole.length) throw new Error(`console issues: ${relevantConsole.join("; ")}`);
  console.log("black-ui QA flow passed");
}

async function addInbound(page, tag, port) {
  await nav(page, "Inbounds");
  await page.getByRole("button", { name: "New", exact: true }).click();
  await page.getByLabel("Tag", { exact: true }).fill(tag);
  await page.getByLabel("Listen host", { exact: true }).fill("127.0.0.1");
  await page.getByLabel("Port", { exact: true }).fill(port);
  await page.getByLabel("Transport", { exact: true }).selectOption("ws");
  await page
    .getByLabel("Stream settings JSON", { exact: true })
    .fill(JSON.stringify({ network: "ws", security: "none", wsSettings: { path: `/${tag}` } }));
  await page.getByRole("button", { name: "Save Inbound", exact: true }).click();
  await page.getByText(tag).waitFor();
}

async function addUser(page, email, inboundLabel) {
  await nav(page, "Users");
  await page.getByRole("button", { name: "Add User", exact: true }).click();
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Inbound", { exact: true }).selectOption({ label: inboundLabel });
  await page.getByLabel("Generate UUID", { exact: true }).click();
  await page.waitForFunction(() => Array.from(document.querySelectorAll("input")).some((input) => input.value.includes("-")));
  await page.getByRole("button", { name: "Save User", exact: true }).click();
  await page.getByText(email, { exact: true }).waitFor();
}

async function nav(page, name) {
  await page.getByRole("button", { name, exact: true }).click();
}

async function strip(page, pattern) {
  await page.waitForFunction((source) => new RegExp(source, "i").test(document.querySelector(".strip-message")?.textContent ?? ""), pattern.source);
}

async function waitForHttp(url) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`timed out waiting for ${url}`);
}

async function waitForPort(port) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      const socket = await import("node:net").then(({ createConnection }) => createConnection({ host: "127.0.0.1", port }));
      await new Promise((resolve, reject) => {
        socket.once("connect", resolve);
        socket.once("error", reject);
      });
      socket.destroy();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new Error(`timed out waiting for port ${port}`);
}

async function run(command, args) {
  const child = spawn(command, args, { cwd: repoRoot, stdio: "inherit" });
  const code = await new Promise((resolve) => child.on("close", resolve));
  if (code !== 0) throw new Error(`${command} ${args.join(" ")} failed with ${code}`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => {
    for (const child of processes.reverse()) child.kill("SIGINT");
  });
