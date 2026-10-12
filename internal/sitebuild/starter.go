package sitebuild

// Starter returns complete, coherent starting content for a template (English
// and Persian). Four templates (corporate, blog, portfolio, app_showcase) are
// full branded websites with their own artwork (see StarterMedia). Identities are fictional; no real businesses,
// people, reviews or contact details are implied. Everything is editable.
func Starter(template string) *Content {
	switch template {
	case "corporate":
		return starterCorporate()
	case "blog":
		return starterBlog()
	case "portfolio":
		return starterPortfolio()
	case "app_showcase":
		return starterApp()
	}
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
