package sitebuild

// Starter returns complete, coherent starting content for a template (English
// and Persian). Identities are fictional and generic; no real businesses,
// people, reviews or contact details are implied. Everything is editable.
func Starter(template string) *Content {
	t := func(en, fa string) L { return L{"en": en, "fa": fa} }
	c := &Content{Site: Site{
		Title:   t("Lumina Studio", "استودیو لومینا"),
		Tagline: t("Design and engineering for the modern web", "طراحی و مهندسی برای وب امروز"),
		Footer:  t("© Lumina Studio — a sample website", "© استودیو لومینا — یک وب‌سایت نمونه"),
		Accent:  "#3b5bdb",
	}}
	home := Page{Slug: "", Title: t("Home", "خانه"), Description: t("Design and engineering studio building fast, reliable websites and apps.", "استودیو طراحی و مهندسی که وب‌سایت‌ها و اپلیکیشن‌های سریع و قابل‌اعتماد می‌سازد.")}

	switch template {
	case "landing":
		c.Site.Title = t("Nimbus", "نیمبوس")
		c.Site.Tagline = t("Launch faster, worry less", "سریع‌تر منتشر کنید، کمتر نگران باشید")
		home.Blocks = []Block{
			{Type: "hero", Heading: t("Everything you need to launch", "هر آنچه برای انتشار لازم دارید"), Text: t("Nimbus brings hosting, delivery and monitoring together so your team ships in minutes, not days.", "نیمبوس میزبانی، تحویل و پایش را کنار هم می‌آورد تا تیم شما در چند دقیقه منتشر کند، نه چند روز."), Label: t("Get started", "شروع کنید"), Href: "#contact"},
			{Type: "features", Heading: t("Built for speed and calm", "ساخته‌شده برای سرعت و آرامش"), Items: []Item{
				{Title: t("Instant delivery", "تحویل آنی"), Text: t("Static assets served from the edge with automatic caching.", "فایل‌های ایستا از لبهٔ شبکه با کش خودکار ارائه می‌شوند.")},
				{Title: t("Always encrypted", "همیشه رمزنگاری‌شده"), Text: t("Automatic certificates and modern TLS on every domain.", "گواهی خودکار و TLS امروزی روی هر دامنه.")},
				{Title: t("Clear insight", "دید شفاف"), Text: t("Real-time health, logs and alerts in one dashboard.", "سلامت، لاگ و هشدار بلادرنگ در یک داشبورد.")},
			}},
			{Type: "quote", Text: t("Software should feel effortless to run. That belief guides every decision we make.", "اجرای نرم‌افزار باید بی‌دردسر باشد؛ این باور راهنمای هر تصمیم ماست.")},
			{Type: "faq", Heading: t("Common questions", "پرسش‌های رایج"), Items: faqItems(t)},
			{Type: "cta", Heading: t("Ready to see it?", "آماده‌اید ببینید؟"), Text: t("Tell us about your project and we will reach out.", "دربارهٔ پروژه‌تان بگویید تا با شما تماس بگیریم."), Label: t("Contact us", "تماس با ما"), Href: "mailto:hello@example.com"},
		}
		c.Pages = []Page{home}

	case "corporate":
		home.Blocks = []Block{
			{Type: "hero", Heading: t("We build software that lasts", "نرم‌افزاری می‌سازیم که ماندگار است"), Text: t("Lumina Studio is a small team of engineers and designers helping organisations ship dependable products.", "استودیو لومینا تیمی کوچک از مهندسان و طراحان است که به سازمان‌ها کمک می‌کند محصولات قابل‌اعتماد منتشر کنند.")},
			{Type: "features", Heading: t("What we do", "چه می‌کنیم"), Items: []Item{
				{Title: t("Product engineering", "مهندسی محصول"), Text: t("Web and mobile applications built to be fast, accessible and maintainable.", "اپلیکیشن‌های وب و موبایل که سریع، در دسترس و قابل‌نگهداری ساخته می‌شوند.")},
				{Title: t("Cloud & reliability", "ابر و پایداری"), Text: t("Resilient infrastructure, automated deployment and clear observability.", "زیرساخت تاب‌آور، استقرار خودکار و مشاهده‌پذیری روشن.")},
				{Title: t("Design systems", "سیستم‌های طراحی"), Text: t("Consistent, responsive interfaces that scale with your product.", "رابط‌های یکدست و واکنش‌گرا که همراه محصول شما رشد می‌کنند.")},
			}},
			{Type: "text", Heading: t("Why teams work with us", "چرا تیم‌ها با ما کار می‌کنند"), Text: t("We stay small on purpose. Every engagement is led by senior people who do the work, communicate clearly, and care about the result long after launch.", "ما به‌عمد کوچک می‌مانیم. هر همکاری را افراد باتجربه‌ای رهبری می‌کنند که خودشان کار می‌کنند، شفاف ارتباط می‌گیرند و تا مدت‌ها پس از انتشار به نتیجه اهمیت می‌دهند.")},
			{Type: "cta", Heading: t("Have a project in mind?", "پروژه‌ای در ذهن دارید؟"), Label: t("Get in touch", "تماس بگیرید"), Href: "mailto:hello@example.com"},
		}
		c.Pages = []Page{home,
			{Slug: "services", Title: t("Services", "خدمات"), Description: t("Product engineering, cloud reliability and design systems.", "مهندسی محصول، پایداری ابری و سیستم‌های طراحی."), Blocks: []Block{
				{Type: "hero", Heading: t("Services", "خدمات"), Text: t("Focused engagements from first idea to steady operation.", "همکاری‌های متمرکز از نخستین ایده تا بهره‌برداری پایدار.")},
				{Type: "features", Items: []Item{
					{Title: t("Discovery & strategy", "کشف و راهبرد"), Text: t("We map the problem, the users and the constraints before writing code.", "پیش از نوشتن کد، مسئله، کاربران و محدودیت‌ها را ترسیم می‌کنیم.")},
					{Title: t("Build & launch", "ساخت و انتشار"), Text: t("Iterative delivery with tests, reviews and safe, reversible releases.", "تحویل تدریجی با تست، بازبینی و انتشارهای ایمن و بازگشت‌پذیر.")},
					{Title: t("Operate & improve", "بهره‌برداری و بهبود"), Text: t("Monitoring, maintenance and steady improvement after go-live.", "پایش، نگهداری و بهبود پیوسته پس از راه‌اندازی.")},
				}},
				{Type: "faq", Heading: t("Working together", "همکاری با هم"), Items: faqItems(t)},
			}},
			{Slug: "about", Title: t("About", "درباره ما"), Description: t("A small senior team focused on dependable software.", "تیمی کوچک و باتجربه با تمرکز بر نرم‌افزار قابل‌اعتماد."), Blocks: []Block{
				{Type: "hero", Heading: t("About Lumina Studio", "دربارهٔ استودیو لومینا"), Text: t("We are engineers and designers who like hard problems and clear solutions.", "ما مهندسان و طراحانی هستیم که مسائل دشوار و راه‌حل‌های روشن را دوست داریم.")},
				{Type: "text", Text: t("Lumina Studio started as a handful of people who kept being asked to rescue stalled projects. Over time that turned into a way of working: understand deeply, build carefully, and leave teams better equipped than we found them.", "استودیو لومینا با چند نفر آغاز شد که بارها برای نجات پروژه‌های متوقف‌مانده دعوت می‌شدند. به‌مرور این به یک شیوهٔ کار تبدیل شد: درک عمیق، ساخت دقیق، و توانمندتر کردن تیم‌ها نسبت به زمانی که به آن‌ها پیوستیم.")},
				{Type: "features", Heading: t("How we work", "چگونه کار می‌کنیم"), Items: []Item{
					{Title: t("Senior-led", "هدایت‌شده با باتجربه‌ها"), Text: t("The people who plan the work also do it.", "کسانی که کار را طراحی می‌کنند، خودشان انجامش می‌دهند.")},
					{Title: t("Transparent", "شفاف"), Text: t("Plain progress, honest trade-offs, no surprises.", "پیشرفت روشن، مصالحه‌های صادقانه، بدون غافلگیری.")},
					{Title: t("Durable", "پایدار"), Text: t("We optimise for the years after launch, not just the demo.", "برای سال‌های پس از انتشار بهینه می‌کنیم، نه فقط نمایش اولیه.")},
				}},
			}},
			{Slug: "contact", Title: t("Contact", "تماس"), Description: t("Get in touch with Lumina Studio.", "با استودیو لومینا در تماس باشید."), Blocks: []Block{
				{Type: "hero", Heading: t("Contact", "تماس")},
				{Type: "text", Text: t("Email **[hello@example.com](mailto:hello@example.com)** with a short description of your project and the outcome you are hoping for. We usually reply within two business days.", "به **[hello@example.com](mailto:hello@example.com)** ایمیل بزنید و شرح کوتاهی از پروژه و نتیجه‌ای که انتظار دارید بنویسید. معمولاً ظرف دو روز کاری پاسخ می‌دهیم.")},
				{Type: "text", Heading: t("Office hours", "ساعات کاری"), Text: t("Monday to Friday, 9:00–17:00. We work remotely with teams in many time zones.", "دوشنبه تا جمعه، ۹ تا ۱۷. به‌صورت دورکاری با تیم‌هایی در مناطق زمانی مختلف کار می‌کنیم.")},
			}},
			{Slug: "faq", Title: t("FAQ", "پرسش‌های رایج"), Description: t("Answers to common questions.", "پاسخ پرسش‌های رایج."), Blocks: []Block{
				{Type: "hero", Heading: t("Frequently asked questions", "پرسش‌های پرتکرار")},
				{Type: "faq", Items: faqItems(t)},
			}},
		}

	case "portfolio":
		c.Site.Title = t("Ava Rahimi", "آوا رحیمی")
		c.Site.Tagline = t("Designer & front-end developer", "طراح و توسعه‌دهندهٔ فرانت‌اند")
		home.Blocks = []Block{
			{Type: "hero", Heading: t("Hi, I'm Ava", "سلام، من آوا هستم"), Text: t("I design and build clean, accessible interfaces for products people enjoy using.", "رابط‌های تمیز و در‌دسترس برای محصولاتی می‌سازم که کاربران از آن‌ها لذت می‌برند.")},
			{Type: "gallery", Heading: t("Selected work", "نمونه‌کارهای منتخب"), Items: []Item{
				{Title: t("Atlas dashboard", "داشبورد اطلس"), Text: t("Analytics interface with a calm, data-dense layout.", "رابط تحلیلی با چیدمان آرام و پرداده.")},
				{Title: t("Meadow store", "فروشگاه مِدو"), Text: t("A fast storefront focused on clarity and trust.", "یک فروشگاه سریع با تمرکز بر شفافیت و اعتماد.")},
				{Title: t("Tide reader", "خوانندهٔ تاید"), Text: t("A distraction-free reading app for long articles.", "اپلیکیشن مطالعهٔ بدون‌حواس‌پرتی برای مقاله‌های بلند.")},
			}},
			{Type: "cta", Heading: t("Let's work together", "با هم کار کنیم"), Label: t("Email me", "به من ایمیل بزنید"), Href: "mailto:hello@example.com"},
		}
		c.Pages = []Page{home,
			{Slug: "about", Title: t("About", "درباره"), Blocks: []Block{
				{Type: "text", Text: t("I have spent the last several years designing and shipping web products, from early prototypes to polished releases. I care about accessibility, performance and interfaces that respect people's time.", "چند سال گذشته را صرف طراحی و انتشار محصولات وب کرده‌ام، از نمونه‌های اولیه تا نسخه‌های نهایی. به دسترس‌پذیری، کارایی و رابط‌هایی که به وقت مردم احترام می‌گذارند اهمیت می‌دهم.")},
			}},
			{Slug: "contact", Title: t("Contact", "تماس"), Blocks: []Block{{Type: "text", Text: t("Reach me at **[hello@example.com](mailto:hello@example.com)**.", "از طریق **[hello@example.com](mailto:hello@example.com)** با من در تماس باشید.")}}},
		}

	case "documentation":
		c.Site.Title = t("Harbor Docs", "مستندات هاربر")
		home.Title = t("Introduction", "مقدمه")
		home.Blocks = []Block{
			{Type: "text", Text: t("Welcome to Harbor, a small library for building reliable background jobs. This guide walks you from installation to production.", "به هاربر خوش آمدید، کتابخانه‌ای کوچک برای ساخت کارهای پس‌زمینهٔ قابل‌اعتماد. این راهنما شما را از نصب تا تولید همراهی می‌کند.")},
			{Type: "features", Heading: t("In this guide", "در این راهنما"), Items: []Item{
				{Title: t("Installation", "نصب")},
				{Title: t("Configuration", "پیکربندی")},
				{Title: t("FAQ", "پرسش‌های رایج")},
			}},
		}
		c.Pages = []Page{home,
			{Slug: "install", Kind: "doc", Title: t("Installation", "نصب"), Blocks: []Block{{Type: "text", Text: t("Add the package to your project, then import it where you schedule work. Harbor has no required configuration to get started.", "بسته را به پروژه اضافه کنید و آن را جایی که کارها را زمان‌بندی می‌کنید وارد کنید. هاربر برای شروع به پیکربندی اجباری نیاز ندارد.")}}},
			{Slug: "configuration", Kind: "doc", Title: t("Configuration", "پیکربندی"), Blocks: []Block{{Type: "text", Text: t("Tune concurrency, retries and timeouts to match your workload. Sensible defaults are provided for each.", "هم‌زمانی، تلاش مجدد و زمان‌های انتظار را متناسب با بار کاری تنظیم کنید. برای هرکدام پیش‌فرض‌های معقول در نظر گرفته شده است.")}}},
			{Slug: "faq", Kind: "doc", Title: t("FAQ", "پرسش‌های رایج"), Blocks: []Block{{Type: "faq", Items: faqItems(t)}}},
		}

	case "blog":
		c.Site.Title = t("Field Notes", "یادداشت‌های میدانی")
		c.Site.Tagline = t("Writing about building software", "نوشته‌هایی دربارهٔ ساخت نرم‌افزار")
		home.Blocks = []Block{
			{Type: "text", Text: t("Short essays on engineering, design and the craft of shipping.", "جستارهای کوتاه دربارهٔ مهندسی، طراحی و هنر انتشار.")},
			{Type: "posts", Heading: t("Latest posts", "تازه‌ترین نوشته‌ها")},
		}
		c.Pages = []Page{home,
			{Slug: "shipping-slowly", Kind: "post", Date: "2026-02-18", Title: t("In praise of shipping slowly", "در ستایش انتشار آهسته"), Description: t("Why careful, reversible releases beat heroics.", "چرا انتشارهای محتاط و بازگشت‌پذیر بر قهرمان‌بازی می‌چربند."), Blocks: []Block{{Type: "text", Text: t("The fastest way to move quickly over time is to make each change small, tested and easy to undo. Speed is a by-product of calm.", "سریع‌ترین راه برای پیشروی پیوسته این است که هر تغییر را کوچک، آزموده و آسان برای بازگشت کنید. سرعت، فرآوردهٔ آرامش است.")}}},
			{Slug: "reading-the-logs", Kind: "post", Date: "2026-01-07", Title: t("Reading the logs", "خواندن لاگ‌ها"), Description: t("A short habit that prevents long outages.", "عادتی کوتاه که از اختلال‌های طولانی جلوگیری می‌کند."), Blocks: []Block{{Type: "text", Text: t("Spend ten minutes a day reading production logs you did not go looking for. You will find the small problems before they become the big ones.", "روزی ده دقیقه لاگ‌های تولید را بخوانید که دنبالشان نبوده‌اید. مشکلات کوچک را پیش از بزرگ‌شدن پیدا می‌کنید.")}}},
		}

	case "app_showcase":
		c.Site.Title = t("Focus", "فوکوس")
		c.Site.Tagline = t("A calmer way to plan your day", "راهی آرام‌تر برای برنامهٔ روز")
		home.Blocks = []Block{
			{Type: "hero", Heading: t("Plan less. Do more.", "کمتر برنامه بریز، بیشتر انجام بده."), Text: t("Focus turns a long to-do list into a short, realistic plan for today — and gets out of your way.", "فوکوس فهرست بلند کارها را به برنامه‌ای کوتاه و واقع‌بینانه برای امروز تبدیل می‌کند و از سر راهت کنار می‌رود."), Label: t("Download", "دانلود"), Href: "#contact"},
			{Type: "features", Heading: t("Why people love Focus", "چرا مردم فوکوس را دوست دارند"), Items: []Item{
				{Title: t("Works offline", "آفلاین کار می‌کند"), Text: t("Your plan is always available, even without a connection.", "برنامه‌ات همیشه در دسترس است، حتی بدون اینترنت.")},
				{Title: t("Private by design", "حریم خصوصی از پایه"), Text: t("Your data stays on your device unless you choose to sync.", "داده‌هایت روی دستگاه می‌ماند مگر آنکه خودت همگام‌سازی را انتخاب کنی.")},
				{Title: t("Beautifully simple", "به‌زیبایی ساده"), Text: t("A clean interface with nothing to learn.", "رابطی تمیز که چیزی برای یادگیری ندارد.")},
			}},
			{Type: "faq", Heading: t("Questions", "پرسش‌ها"), Items: faqItems(t)},
			{Type: "cta", Heading: t("Try Focus today", "امروز فوکوس را امتحان کنید"), Label: t("Get the app", "دریافت اپ"), Href: "#contact"},
		}
		c.Pages = []Page{home}

	default:
		home.Blocks = []Block{{Type: "hero", Heading: t("Welcome", "خوش آمدید"), Text: t("A website built with NGM.", "وب‌سایتی ساخته‌شده با NGM.")}}
		c.Pages = []Page{home}
	}
	return c
}

// faqItems is a reusable set of neutral, non-impersonating FAQ entries.
func faqItems(t func(string, string) L) []Item {
	return []Item{
		{Title: t("How do we get started?", "چطور شروع کنیم؟"), Text: t("Send a short note describing your project. We reply with a few questions and suggested next steps.", "یادداشت کوتاهی دربارهٔ پروژه بفرستید. با چند پرسش و گام‌های پیشنهادی پاسخ می‌دهیم.")},
		{Title: t("What does a project cost?", "هزینهٔ یک پروژه چقدر است؟"), Text: t("It depends on scope. After a short discovery call we share a clear, written estimate before any work begins.", "به دامنهٔ کار بستگی دارد. پس از یک گفت‌وگوی کوتاهِ کشف، پیش از آغاز کار برآوردی روشن و مکتوب ارائه می‌دهیم.")},
		{Title: t("Do you work remotely?", "دورکاری می‌کنید؟"), Text: t("Yes. We collaborate with teams across many time zones and keep communication clear and regular.", "بله. با تیم‌هایی در مناطق زمانی مختلف همکاری می‌کنیم و ارتباط را روشن و منظم نگه می‌داریم.")},
		{Title: t("What happens after launch?", "پس از انتشار چه می‌شود؟"), Text: t("We can stay on for monitoring, maintenance and improvements, or hand everything over with documentation.", "می‌توانیم برای پایش، نگهداری و بهبود همراه بمانیم، یا همه‌چیز را همراه با مستندات تحویل دهیم.")},
	}
}
