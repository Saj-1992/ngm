// Phase 8 UI QA against the live VM: every navigation page × desktop/tablet/mobile × en/fa.
// Checks: no horizontal overflow, correct dir/lang, no console/page errors, no untranslated
// message keys, and axe-core WCAG 2.x A/AA (desktop). Screenshots go to dist/qa/ (git-ignored).
const fs = require("fs");
const path = require("path");
const H = require("./harness.cjs");
const puppeteer = require("../remote/node_modules/puppeteer-core");
const axeSrc = fs.readFileSync(require.resolve("../remote/node_modules/axe-core/axe.min.js"), "utf8");
const EDGE = process.env.QA_BROWSER || "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe";
const pagesAll = ["/", ...[...fs.readFileSync("web/src/nav.ts", "utf8").matchAll(/path: "(\/[^"]+)"/g)].map((m) => m[1])];
const pages = process.env.QA_PAGES ? process.env.QA_PAGES.split(",") : pagesAll;
const keys = [...fs.readFileSync("web/src/i18n/messages.ts", "utf8").matchAll(/^  "([a-z0-9]+\.[A-Za-z0-9.]+)":/gm)].map((m) => m[1]);
const VPS = { desktop: [1440, 900], tablet: [834, 1112], mobile: [390, 844] };
const OUT = "dist/qa";

H.start(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const { cookie } = H.session();
  const prof = fs.mkdtempSync(path.resolve("dist/qa-profile-"));
  const browser = await puppeteer.launch({ executablePath: EDGE, headless: true, userDataDir: prof, args: ["--no-first-run", "--disable-extensions", "--disable-gpu"] });
  const problems = [], a11y = {};
  let n = 0;
  try {
    for (const loc of (process.env.QA_LOCALES || "en,fa").split(",")) {
      for (const [vp, [w, h]] of Object.entries(VPS).filter(([k]) => !process.env.QA_VPS || process.env.QA_VPS.split(",").includes(k))) {
        const page = await browser.newPage();
        await page.setViewport({ width: w, height: h });
        await page.setCookie({ name: "ngm_session", value: cookie.split("=")[1], domain: "127.0.0.1", path: "/" });
        await page.evaluateOnNewDocument((l) => localStorage.setItem("ngm.locale", l), loc);
        const errs = [];
        page.on("pageerror", (e) => errs.push("pageerror " + e.message));
        page.on("console", (m) => m.type() === "error" && errs.push("console " + m.text()));
        for (const p of pages) {
          errs.length = 0;
          await page.goto("http://127.0.0.1:19998" + p, { waitUntil: "networkidle2", timeout: 30000 });
          await new Promise((r) => setTimeout(r, 800));
          const r = await page.evaluate((ks) => {
            const t = document.body.innerText;
            return { over: document.documentElement.scrollWidth - window.innerWidth, dir: document.documentElement.dir, lang: document.documentElement.lang,
              raw: ks.filter((k) => new RegExp("(^|[^A-Za-z0-9._-])" + k.replace(/\./g, "\\.") + "($|[^A-Za-z0-9._-])").test(t)).slice(0, 5), title: document.title };
          }, keys);
          const id = `${loc}-${vp}-${p.replace(/\//g, "_") || "_"}`;
          if (r.over > 1) problems.push(`${id}: horizontal overflow ${r.over}px`);
          if (r.over > 1 && process.env.QA_DETAIL) console.log("DETAIL wide", id, await page.evaluate(() => [...document.querySelectorAll("body *")].filter((e) => e.getBoundingClientRect().right > window.innerWidth + 1).slice(0, 6).map((e) => e.tagName + "." + String(e.className).slice(0, 90) + " w=" + Math.round(e.getBoundingClientRect().width)).join(" || ")));
          if (r.dir !== (loc === "fa" ? "rtl" : "ltr") || r.lang !== loc) problems.push(`${id}: dir=${r.dir} lang=${r.lang}`);
          if (r.raw.length) problems.push(`${id}: untranslated ${r.raw.join(",")}`);
          const real = errs.filter((e) => !/401|Failed to load resource/.test(e));
          if (real.length) problems.push(`${id}: ${real.slice(0, 2).join(" ; ").slice(0, 200)}`);
          await page.screenshot({ path: path.join(OUT, id + ".png") });
          if (vp === "desktop") {
            await page.evaluate(axeSrc);
            const res = await page.evaluate(() => window.axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"] }));
            for (const v of res.violations) {
              const k = `${v.impact}:${v.id}`;
              (a11y[k] = a11y[k] || new Set()).add(`${loc}${p}(${v.nodes.length})`);
              if (process.env.QA_DETAIL) for (const nd of v.nodes.slice(0, 4)) console.log("DETAIL", k, loc + p, nd.html.slice(0, 140), (nd.any[0] && nd.any[0].message || "").slice(0, 160));
            }
          }
          n++;
        }
        await page.close();
      }
    }
  } finally {
    await browser.close();
    try { fs.rmSync(prof, { recursive: true, force: true }); } catch {}
  }
  fs.writeFileSync(path.join(OUT, "report.json"), JSON.stringify({ problems, a11y: Object.fromEntries(Object.entries(a11y).map(([k, v]) => [k, [...v]])) }, null, 1));
  check("ui-layout", problems.length === 0, `${n} page views (${pages.length} pages × 3 viewports × 2 locales); problems: ${problems.length ? problems.slice(0, 12).join(" | ") : "none"}`);
  const serious = Object.keys(a11y).filter((k) => /^(critical|serious)/.test(k));
  check("ui-axe", serious.length === 0, `axe WCAG 2.x A/AA on ${pages.length * 2} desktop views; ${Object.entries(a11y).map(([k, v]) => `${k} on ${v.size}`).join("; ") || "no violations"}`);
});
function check(n, ok, d) { H.check(n, ok, d); }
