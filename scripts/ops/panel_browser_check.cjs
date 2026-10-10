const puppeteer = require("../remote/node_modules/puppeteer-core");
const fs = require("fs");
const CHROME = process.env.QA_BROWSER || "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe";
const URL = process.argv[2];
(async () => {
  const prof = fs.mkdtempSync("D:/Sajjad/NGM/dist/pb-");
  const b = await puppeteer.launch({ executablePath: CHROME, headless: true, userDataDir: prof, args: ["--no-first-run", "--disable-gpu"] });
  const errs = [];
  try {
    const p = await b.newPage();
    p.on("pageerror", (e) => errs.push("pageerror " + e.message));
    p.on("console", (m) => m.type() === "error" && errs.push("console " + m.text()));
    const resp = await p.goto(URL, { waitUntil: "networkidle2", timeout: 45000 });
    await new Promise((r) => setTimeout(r, 1500));
    const info = await p.evaluate(() => ({
      title: document.title,
      base: document.querySelector("base")?.getAttribute("href"),
      bodyLen: document.body.innerText.length,
      text: document.body.innerText.slice(0, 120),
      hasRoot: !!document.querySelector("#root")?.children.length,
    }));
    console.log("STATUS", resp.status());
    console.log("INFO", JSON.stringify(info));
    console.log("ERRORS", errs.filter((e) => !/401|Failed to load resource.*401/.test(e)).slice(0, 5).join(" | ") || "none");
  } finally {
    await b.close();
    try { fs.rmSync(prof, { recursive: true, force: true }); } catch {}
  }
})();
