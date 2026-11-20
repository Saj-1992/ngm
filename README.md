# NGM — مدیر جامع دروازهٔ Nginx (Nginx Gateway Manager)

**NGM** یک کنترل‌پنل و مدیر دروازهٔ کامل، امن و تک‌باینری (Go + React/TypeScript) برای مدیریت حرفه‌ای **Nginx** روی سرورهای لینوکس است. تمام تغییرات پیکربندی از چرخهٔ **Safe Apply** عبور می‌کنند: اعتبارسنجی مدل ← آماده‌سازی در مسیر ایزوله (Stage) ← تست `nginx -t` ← Reload ← راستی‌آزمایی زنده (Probe) همراه با **بازگشت خودکار (Auto-Rollback)** به آخرین وضعیت سالم در صورت بروز خطا.

---

## پیش‌نیازها
- سیستم‌عامل **Ubuntu 22.04 / 24.04 / 26.04 LTS** (معماری `amd64` یا `arm64`)
- دسترسی `root`
- بستهٔ `nginx` و ماژول `libnginx-mod-stream` (در صورت نبودن، توسط نصب‌کننده نصب می‌شوند)
- نصب‌کننده و سرویس‌های NGM هرگز فایل‌های Nginx یا قوانین UFW متعلق به سرویس‌های دیگر را تغییر نمی‌دهند. برای پذیرش Nginx سفارشی موجود از فلگ `--adopt-existing-nginx` استفاده کنید.

---

## نصب سریع (امضاشده و تک‌خطی)
```sh
curl -fsSL https://github.com/Saj-1992/ngm/releases/latest/download/install.sh | sudo sh
```
اسکریپت نصب، آخرین نسخهٔ منتشرشده را دانلود کرده، امضای **Ed25519** فایل `manifest.json` و هش **SHA-256** باینری را بررسی می‌کند و سپس `ngm install` را اجرا می‌نماید. در صورت هرگونه مغایرت، نصب متوقف شده و هیچ تغییری روی سیستم اعمال نمی‌شود.

برای اطمینان بیشتر (Pin کردن کلید ناشر):
```sh
curl -fsSL https://github.com/Saj-1992/ngm/releases/latest/download/install.sh -o install.sh
sudo NGM_EXPECT_KEY=sha256:<published-fingerprint> sh install.sh
```
نصب آفلاین:
```sh
sudo sh install.sh --from /path/to/release/dir
```

### راه‌اندازی اولیه (First-Run Setup)
پس از نصب، با تونل SSH به پورت محلی کنترل‌پنل متصل شوید:
```sh
ssh -L 9999:127.0.0.1:9999 root@<server-ip>
```
سپس نشانی `http://127.0.0.1:9999/setup` را در مرورگر باز کرده و با استفاده از **Bootstrap Token** چاپ‌شده در خروجی نصب (`ngm admin bootstrap-token` برای ساخت توکن جدید) حساب مالک (Owner) و احراز هویت دوعاملی (TOTP) را فعال کنید.

---

## امکانات جامع پروژه

### ۱. مسیریابی و Gateway پیشرفته
- **پشتیبانی از HTTP، HTTPS، TCP و UDP (لایه ۴):** مدیریت کامل Listenerها و Poolهای بک‌اند.
- **TLS Passthrough و SNI Routing روی پورت ۴۴۳ مشترک:** توزیع هوشمند ترافیک با `ssl_preread` بین مسیرهای Passthrough و Terminate.
- **پشتیبانی از WebSocket و gRPC (`grpc_pass`)** به‌صورت بومی در سطح Route.
- **سیاست‌های ترافیکی و امنیتی در سطح هر Route:**
  - **Rate Limiting اختصاصی:** محدودسازی درخواست بر ثانیه (`limit_req_zone`) و ظرفیت Burst به ازای هر Route (با پاسخ ۴۲۹).
  - **IP Allowlist / Denylist:** محدودسازی دسترسی بر پایهٔ آدرس IP و رنج CIDR.
  - **Strip Prefix:** حذف خودکار پیشوند مسیر تطبیق‌یافته پیش از ارسال به بک‌اند.
  - **مدیریت CORS و هدرهای سفارشی:** تنظیم هدرهای درخواست/پاسخ و پاسخ خودکار به Preflight (`OPTIONS`) با اعتبارسنجی ضد تزریق دایرکتیو.
  - **فشرده‌سازی Gzip** در سطح Route.
- **بازیابی IP واقعی کاربر (Trusted Proxies / Real-IP):** پشتیبانی آماده از رنج‌های Cloudflare و پروکسی‌های مورد اعتماد (`set_real_ip_from` و `real_ip_header`).
- **شبیه‌ساز مسیریابی (Simulation Lab) و پیش‌نمایش Diff:** آزمایش مسیرها پیش از استقرار و مشاهدهٔ مقایسهٔ خط‌به‌خط (**Config Diff**) بین پیکربندی Active و Desired.
- **وب‌سایت Fallback (ADR-036):** پاسخ‌دهی با یک وب‌سایت واقعی و گواهی معتبر به درخواست‌های بدون Host یا با SNI ناشناس.

### ۲. دامنه، DNS، کلادفلر و گواهی‌های SSL/TLS
- **ثبت دامنه و پایش DNS:** بررسی مداوم رکوردهای `A / AAAA / CNAME / CAA / NS / TXT` روی سرورهای Authoritative و Resolverها.
- **یکپارچه‌سازی امن با Cloudflare DNS:** کشف Zoneها، ساخت خودکار زیردامنه، پیش‌نمایش تغییرات پیش از اعمال و حفظ رکوردهایی که متعلق به NGM نیستند.
- **صدور و تمدید خودکار گواهی SSL (ACME / Let's Encrypt):** پشتیبانی از چالش‌های `HTTP-01` و `DNS-01` (شامل گواهی‌های Wildcard) و دانلود امن `fullchain.pem` / `privkey.pem` (با Step-up MFA).

### ۳. وب‌سایت‌ساز استاتیک و دوزبانه
- **چهار قالب کامل و آماده (شرکتی، وبلاگ، پورتفولیو، معرفی اپلیکیشن):** دوزبانه (فارسی RTL و انگلیسی LTR)، تاریخ شمسی برای مخاطب فارسی، SEO/Sitemap خودکار، تصاویر و صفحهٔ ۴۰۴ اختصاصی.
- **آپلود فایل ZIP ایمن:** همراه با بررسی‌های ضد Path Traversal، Symlink و Zip Bomb.
- **پیشنمایش ایزوله (Isolated Origin Preview)** و انتشار اتمیک با قابلیت بازگشت آنی به نسخه‌های قبلی.

### ۴. امنیت، احراز هویت و کنترل دسترسی
- **معماری جداسازی اختیارات (Privilege Separation):** پنج سرویس مجزای systemd (`ngm-api`، `ngm-ops`، `ngm-helper`، `ngm-monitor`، `ngm-log-indexer`)؛ هندلرهای API هیچ دستور سیستمی اجرا نمی‌کنند و ارتباط با `ngm-helper` از طریق Unix Socket با بررسی Peer Credentials و عملیات Allowlistشده انجام می‌شود.
- **احراز هویت چندعاملی (TOTP MFA) و کدهای بازیابی:** ورود دوعاملی اجباری، کدهای بازیابی یک‌بارمصرف (`XXXX-XXXX`)، Step-up MFA برای عملیات حساس، و توکن‌های API با دسترسی محدود (Scoped).
- **کنترل دسترسی مبتنی بر نقش (RBAC):** نقش‌های Owner، Admin، Operator، Viewer و نقش‌های سفارشی با محدودهٔ دسترسی مشخص.
- **گزارش ممیزی ضد دستکاری (Tamper-Evident Audit Log):** زنجیرهٔ هش‌شده برای تمام رویدادهای امنیتی.
- **گاوصندوق رمزنگاری‌شده (Vault):** رمزنگاری AES-256-GCM با کلیدهای نسخه‌دار (KEK) و پشتیبانی از چرخش بدون وقفه.

### ۵. فایروال، پشتیبان‌گیری، پایش و رصدپذیری
- **مدیریت فایروال UFW:** دفتر کل قوانین متعلق به NGM بدون پاک کردن قوانین خارجی، همراه با محافظت از دسترسی SSH و تایمر بازگشت اضطراری (Dead-man Watchdog).
- **پشتیبان‌گیری رمزنگاری‌شده (محلی و ابری S3):** فرمت قابل‌حمل `NGMBAK1` (Argon2id + AEAD) قابل بازیابی روی سرور جدید، زمان‌بندی خودکار، و **ارسال خودکار به باکت‌های سازگار با S3** (AWS، Cloudflare R2، MinIO، آروان و ...).
- **رصدپذیری و تحلیل ترافیک:**
  - داشبورد تحلیل ترافیک HTTP (نرخ درخواست، تفکیک `2xx/3xx/4xx/5xx`، میانگین و `P95` تأخیر، دامنه‌ها و مسیرهای پربازدید).
  - **خروجی استاندارد Prometheus / OpenMetrics** در مسیر `/api/v1/metrics`.
  - جستجوگر لاگ ساختاریافته (JSONL + FTS5)، Live Tail با SSE و خروجی CSV/JSONL/TXT.
  - گراف توپولوژی و تحلیلگر تأثیر وابستگی‌ها پیش از حذف منابع.
  - هشداردهی از طریق Telegram و Webhook (با محافظت کامل در برابر SSRF و DNS Rebinding).
- **رابط کاربری دوزبانه (فارسی/انگلیسی) با تم روشن/تاریک، پالت دستورات سریع (`Ctrl+K`) و Tooltipهای راهنما روی تمام بخش‌ها.**

---

## دستورات کاربردی CLI
| عملیات | دستور |
|---|---|
| وضعیت سرویس‌ها و عیب‌یابی | `ngm status`, `ngm doctor` |
| تست کامل پیکربندی Nginx | `ngm config test` |
| بازگشت به نسل قبلی پیکربندی | `ngm rollback [GENERATION]` |
| مدیریت بکاپ و بازیابی | `ngm backup set-passphrase`, `ngm backup create`, `ngm restore --preview FILE` |
| بازگشت اضطراری فایروال | `ngm fw-revert` |
| بازسازی ایندکس لاگ‌ها | `ngm logs reindex` |
| چرخش کلید Vault | `ngm vault status \| rotate \| retire N` |
| بازنشانی رمز یا MFA کاربر | `ngm admin reset USER` |
| بروزرسانی و بازگشت نسخه | `ngm update check --from DIR`, `sudo ngm update apply --from DIR --yes` |
| تعمیر یا حذف برنامه | `sudo ngm repair`, `sudo ngm uninstall --keep-data \| --purge` |

---

## مستندات فنی
[MASTER_SPEC.md](MASTER_SPEC.md) · [SECURITY_MODEL.md](SECURITY_MODEL.md) · [DEPLOYMENT_CONTRACT.md](DEPLOYMENT_CONTRACT.md) · [API_CONTRACT.md](API_CONTRACT.md) ([openapi.json](api/openapi.json)) · [DECISIONS.md](DECISIONS.md) · [PROGRESS.md](PROGRESS.md) · [TEST_REPORT.md](TEST_REPORT.md)
