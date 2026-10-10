package sitebuild

// Starter returns editable starting content for a template (English and
// Persian texts; other locales fall back to the default until translated).
func Starter(template string) *Content {
	t := func(en, fa string) L { return L{"en": en, "fa": fa} }
	c := &Content{Site: Site{Title: t("My site", "سایت من"), Tagline: t("Built with NGM", "ساخته‌شده با NGM"), Footer: t("© My site", "© سایت من")}}
	home := Page{Slug: "", Title: t("Home", "خانه")}
	switch template {
	case "landing":
		home.Blocks = []Block{
			{Type: "hero", Heading: t("A clear promise in one line", "یک وعدهٔ روشن در یک خط"), Text: t("Explain the value in one or two sentences.", "ارزش کار را در یک یا دو جمله توضیح دهید."), Label: t("Get started", "شروع کنید"), Href: "#contact"},
			{Type: "features", Heading: t("Why choose us", "چرا ما"), Items: []Item{
				{Title: t("Fast", "سریع"), Text: t("Static pages served directly by Nginx.", "صفحه‌های ایستا که مستقیم با Nginx ارائه می‌شوند.")},
				{Title: t("Secure", "امن"), Text: t("No server-side code runs.", "هیچ کد سمت سروری اجرا نمی‌شود.")},
				{Title: t("Bilingual", "دوزبانه"), Text: t("Persian and English with correct direction.", "فارسی و انگلیسی با جهت درست.")},
			}},
			{Type: "cta", Heading: t("Ready?", "آماده‌اید؟"), Label: t("Contact us", "تماس با ما"), Href: "mailto:hello@example.com"},
		}
		c.Pages = []Page{home}
	case "corporate":
		home.Blocks = []Block{
			{Type: "hero", Heading: t("Company name", "نام شرکت"), Text: t("What the company does, for whom.", "شرکت چه کاری برای چه کسانی انجام می‌دهد.")},
			{Type: "features", Heading: t("Services", "خدمات"), Items: []Item{{Title: t("Consulting", "مشاوره")}, {Title: t("Delivery", "اجرا")}, {Title: t("Support", "پشتیبانی")}}},
		}
		c.Pages = []Page{home,
			{Slug: "about", Title: t("About", "درباره ما"), Blocks: []Block{{Type: "text", Text: t("Our story.", "داستان ما.")}}},
			{Slug: "contact", Title: t("Contact", "تماس"), Blocks: []Block{{Type: "text", Text: t("Email: [hello@example.com](mailto:hello@example.com)", "ایمیل: [hello@example.com](mailto:hello@example.com)")}}},
		}
	case "portfolio":
		home.Blocks = []Block{
			{Type: "hero", Heading: t("Your name", "نام شما"), Text: t("Designer and developer.", "طراح و توسعه‌دهنده.")},
			{Type: "gallery", Heading: t("Selected work", "نمونه‌کارها"), Items: []Item{{Title: t("Project one", "پروژهٔ اول"), Text: t("Short description.", "توضیح کوتاه.")}, {Title: t("Project two", "پروژهٔ دوم")}}},
		}
		c.Pages = []Page{home, {Slug: "about", Title: t("About", "درباره"), Blocks: []Block{{Type: "text", Text: t("A few words about you.", "چند کلمه دربارهٔ شما.")}}}}
	case "documentation":
		home.Title = t("Introduction", "مقدمه")
		home.Blocks = []Block{{Type: "text", Text: t("Start here. Each page appears in the sidebar.", "از اینجا شروع کنید. هر صفحه در نوار کناری می‌آید.")}}
		c.Pages = []Page{home,
			{Slug: "install", Kind: "doc", Title: t("Installation", "نصب"), Blocks: []Block{{Type: "text", Text: t("Step 1 …", "گام ۱ …")}}},
			{Slug: "faq", Kind: "doc", Title: t("FAQ", "پرسش‌های رایج"), Blocks: []Block{{Type: "faq", Items: []Item{{Title: t("A question?", "یک پرسش؟"), Text: t("An answer.", "یک پاسخ.")}}}}},
		}
	case "blog":
		home.Blocks = []Block{{Type: "text", Text: t("Notes and articles.", "یادداشت‌ها و مقاله‌ها.")}, {Type: "posts", Heading: t("Latest posts", "تازه‌ترین نوشته‌ها")}}
		c.Pages = []Page{home,
			{Slug: "hello-world", Kind: "post", Date: "2026-01-01", Title: t("Hello world", "سلام دنیا"), Description: t("The first post.", "نخستین نوشته."), Blocks: []Block{{Type: "text", Text: t("Write here.", "اینجا بنویسید.")}}},
		}
	case "app_showcase":
		home.Blocks = []Block{
			{Type: "hero", Heading: t("App name", "نام اپلیکیشن"), Text: t("The app in one sentence.", "اپلیکیشن در یک جمله."), Label: t("Download", "دانلود"), Href: "https://example.com/download"},
			{Type: "features", Heading: t("Features", "ویژگی‌ها"), Items: []Item{{Title: t("Offline", "آفلاین")}, {Title: t("Private", "حریم خصوصی")}, {Title: t("Simple", "ساده")}}},
			{Type: "faq", Heading: t("Questions", "پرسش‌ها"), Items: []Item{{Title: t("Is it free?", "رایگان است؟"), Text: t("Yes.", "بله.")}}},
		}
		c.Pages = []Page{home}
	default:
		c.Pages = []Page{home}
	}
	return c
}
