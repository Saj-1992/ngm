package sitebuild

// starterPortfolio is a complete studio portfolio: a brand and interface
// design studio. The brand is fictional; all details are editable.
func starterPortfolio() *Content {
	c := &Content{Site: Site{
		Title:   tr("Atelier Dena", "آتلیه دنا"),
		Tagline: tr("Brand identity and interface design studio.", "استودیوی هویت بصری و طراحی رابط کاربری."),
		Footer:  tr("© Atelier Dena. Independent design studio.\nstudio@atelier-dena.example", "© آتلیه دنا. استودیوی مستقل طراحی.\nstudio@atelier-dena.example"),
		Accent:  "#b4571f",
	}}
	works := []Item{
		itImg("work-1.png", "Parsa Bank — design system", "بانک پارسا — سیستم طراحی", "A component library and tokens used by eleven product teams, cutting UI delivery time by a third.", "کتابخانهٔ مؤلفه و توکن‌های طراحی که یازده تیم محصول از آن استفاده می‌کنند و زمان تحویل رابط را یک‌سوم کم کرده است."),
		itImg("work-2.png", "Saffron & Co. — brand identity", "زعفران و شرکا — هویت بصری", "Name, logo, packaging and shopfront for a specialty spice merchant.", "نام، آرم، بسته‌بندی و فروشگاه برای یک تاجر ادویهٔ ویژه."),
		itImg("work-3.png", "Daryā Resort — website", "اقامتگاه دریا — وب‌سایت", "A fast, multilingual booking website that raised direct reservations by 40%.", "وب‌سایت سریع و چندزبانهٔ رزرو که رزروهای مستقیم را ۴۰٪ افزایش داد."),
		itImg("work-4.png", "Tarh Mobile — app interface", "اپلیکیشن طرح — رابط موبایل", "Onboarding and daily-planning flows for a productivity app with 200k users.", "جریان آشناسازی و برنامه‌ریزی روزانه برای اپ بهره‌وری با ۲۰۰ هزار کاربر."),
		itImg("work-5.png", "Kavir Museum — signage", "موزهٔ کویر — تابلوها", "Wayfinding and exhibition graphics for a desert natural-history museum.", "مسیریابی و گرافیک نمایشگاه برای موزهٔ تاریخ طبیعی کویر."),
		itImg("work-6.png", "Sepehr Analytics — dashboard", "تحلیل سپهر — داشبورد", "A calm, data-dense dashboard for logistics operators, tested with 30 users.", "داشبوردی آرام و پرداده برای اپراتورهای لجستیک که با ۳۰ کاربر آزموده شد."),
	}
	home := Page{Slug: "", Title: tr("Home", "خانه"), Description: tr("Atelier Dena designs brand identities, websites and product interfaces for ambitious teams.", "آتلیه دنا هویت بصری، وب‌سایت و رابط محصول را برای تیم‌های جاه‌طلب طراحی می‌کند."), Image: "hero-studio.png", Blocks: []Block{
		{Type: "hero", Image: "hero-studio.png", Heading: tr("Design that makes brands easy to trust", "طراحی که اعتماد به برند را آسان می‌کند"), Text: tr("Atelier Dena is a six-person studio. We shape brand identities, websites and product interfaces for teams who care about clarity, craft and measurable results.", "آتلیه دنا استودیویی شش‌نفره است. هویت بصری، وب‌سایت و رابط محصول را برای تیم‌هایی شکل می‌دهیم که به شفافیت، ظرافت و نتیجهٔ قابل‌اندازه‌گیری اهمیت می‌دهند."), Label: tr("See our work", "نمونه‌کارها"), Href: "page:work"},
		{Type: "gallery", Heading: tr("Selected work", "نمونه‌کارهای منتخب"), Items: works[:3]},
		{Type: "stats", Items: []Item{
			it("80+", "بیش از ۸۰", "projects completed", "پروژهٔ انجام‌شده"),
			it("12", "۱۲", "years in practice", "سال فعالیت"),
			it("9", "۹", "design awards", "جایزهٔ طراحی"),
		}},
		{Type: "quote", Heading: tr("— Head of Product, Parsa Bank", "— مدیر محصول، بانک پارسا"), Text: tr("Dena didn't hand us a style guide; they handed us a way of working. Our teams still use it every day.", "دنا برای ما دفترچهٔ سبک نداد؛ شیوهٔ کار داد. تیم‌های ما هنوز هر روز از آن استفاده می‌کنند.")},
		{Type: "cta", Heading: tr("Let's make something clear", "بیایید چیزی شفاف بسازیم"), Text: tr("We take on a handful of projects each quarter. Tell us about yours.", "هر فصل چند پروژه می‌پذیریم. از پروژهٔ خود بگویید."), Label: tr("Start a project", "شروع پروژه"), Href: "page:contact"},
	}}
	work := Page{Slug: "work", Title: tr("Work", "نمونه‌کارها"), Description: tr("Brand identities, websites and interfaces by Atelier Dena.", "هویت بصری، وب‌سایت و رابط‌های آتلیه دنا."), Blocks: []Block{
		{Type: "hero", Heading: tr("Work", "نمونه‌کارها"), Text: tr("A selection of recent projects across finance, hospitality, retail and culture.", "گزیده‌ای از پروژه‌های اخیر در مالی، گردشگری، خرده‌فروشی و فرهنگ.")},
		{Type: "gallery", Items: works},
	}}
	services := Page{Slug: "services", Title: tr("Services", "خدمات"), Description: tr("Brand identity, web and product design with transparent packages.", "هویت بصری، طراحی وب و محصول با بسته‌های شفاف."), Blocks: []Block{
		{Type: "hero", Heading: tr("Services and packages", "خدمات و بسته‌ها"), Text: tr("Fixed scopes and prices, so you know what you get before we begin.", "دامنه و قیمت ثابت تا پیش از آغاز بدانید چه می‌گیرید.")},
		{Type: "pricing", Label: tr("Request a quote", "درخواست قیمت"), Items: []Item{
			{Title: tr("Identity", "هویت"), Text: tr("Logo, colour, type and usage guide.\n**From 180M IRR** · 4–6 weeks", "آرم، رنگ، تایپ و راهنمای استفاده.\n**از ۱۸۰ میلیون ریال** · ۴ تا ۶ هفته"), Href: "page:contact"},
			{Title: tr("Website", "وب‌سایت"), Text: tr("Strategy, design and build of a fast multilingual site.\n**From 320M IRR** · 6–10 weeks", "راهبرد، طراحی و ساخت سایت سریع چندزبانه.\n**از ۳۲۰ میلیون ریال** · ۶ تا ۱۰ هفته"), Href: "page:contact"},
			{Title: tr("Product", "محصول"), Text: tr("Research, flows and interface for an app or dashboard.\n**From 480M IRR** · 8–14 weeks", "پژوهش، جریان‌ها و رابط برای اپ یا داشبورد.\n**از ۴۸۰ میلیون ریال** · ۸ تا ۱۴ هفته"), Href: "page:contact"},
		}},
		{Type: "steps", Heading: tr("Our process", "فرایند ما"), Items: []Item{
			it("Listen", "گوش دادن", "Workshops with your team and customers to find the real problem.", "کارگاه با تیم و مشتریان شما برای یافتن مسئلهٔ اصلی."),
			it("Explore", "کاوش", "Sketches and prototypes shown early, before decisions are expensive.", "طرح و نمونهٔ اولیه که زود نشان داده می‌شود، پیش از آنکه تصمیم‌ها گران شوند."),
			it("Refine", "پرداخت", "Detail, accessibility and testing with real users.", "جزئیات، دسترس‌پذیری و آزمون با کاربران واقعی."),
			it("Hand over", "تحویل", "Files, guidelines and training so your team can carry on.", "فایل‌ها، راهنما و آموزش تا تیم شما بتواند ادامه دهد."),
		}},
	}}
	about := Page{Slug: "about", Title: tr("About", "درباره"), Description: tr("The people and principles behind Atelier Dena.", "افراد و اصول پشت آتلیه دنا."), Blocks: []Block{
		{Type: "hero", Heading: tr("About the studio", "دربارهٔ استودیو"), Text: tr("We are a small studio on purpose: every client works directly with the people designing.", "استودیوی کوچکی هستیم و این عمدی است: هر مشتری مستقیم با طراحان کار می‌کند.")},
		{Type: "text", Text: tr("Atelier Dena was founded in 2014 by Dena Hosseini after a decade in agencies. She wanted a place where research, craft and engineering sat at the same table.\n\nWe believe good design is mostly editing. We remove what is unnecessary until what remains is obvious. We measure results, and we are happy to be held to them.", "آتلیه دنا در سال ۱۳۹۳ توسط دنا حسینی پس از یک دهه کار در آژانس‌ها تأسیس شد. او جایی می‌خواست که پژوهش، ظرافت و مهندسی پشت یک میز بنشینند.\n\nباور داریم طراحی خوب بیشتر ویرایش است. آنچه لازم نیست را حذف می‌کنیم تا آنچه می‌ماند بدیهی باشد. نتیجه را اندازه می‌گیریم و خوشحال می‌شویم به آن پایبند باشیم.")},
		{Type: "team", Heading: tr("The team", "تیم"), Items: []Item{
			it("Dena Hosseini", "دنا حسینی", "Founder and creative director.", "بنیان‌گذار و مدیر هنری."),
			it("Arman Safavi", "آرمان صفوی", "Lead interface designer.", "طراح ارشد رابط."),
			it("Ladan Mirzaei", "لادن میرزایی", "Brand strategist.", "استراتژیست برند."),
			it("Pouya Karimi", "پویا کریمی", "Front-end engineer.", "مهندس فرانت‌اند."),
		}},
	}}
	contact := Page{Slug: "contact", Title: tr("Contact", "تماس"), Description: tr("Start a project with Atelier Dena.", "پروژه‌ای را با آتلیه دنا آغاز کنید."), Blocks: []Block{
		{Type: "hero", Heading: tr("Start a project", "شروع پروژه"), Text: tr("Tell us what you are building, the timeline and a rough budget. We reply within two working days.", "بگویید چه می‌سازید، زمان‌بندی و بودجهٔ تقریبی. ظرف دو روز کاری پاسخ می‌دهیم.")},
		{Type: "contact", Items: []Item{
			it("Email", "ایمیل", "[studio@atelier-dena.example](mailto:studio@atelier-dena.example)", "[studio@atelier-dena.example](mailto:studio@atelier-dena.example)"),
			it("Studio", "استودیو", "Unit 5, 22 Gandhi St, Tehran", "تهران، خیابان گاندی، پلاک ۲۲، واحد ۵"),
			it("Phone", "تلفن", "[+98 21 5550 3300](tel:+982155503300)", "[۰۲۱-۵۵۵۰۳۳۰۰](tel:+982155503300)"),
			it("Hours", "ساعات کاری", "Saturday–Wednesday 9:30–17:30", "شنبه تا چهارشنبه ۹:۳۰ تا ۱۷:۳۰"),
		}},
	}}
	privacy := Page{Slug: "privacy", Title: tr("Privacy", "حریم خصوصی"), Blocks: []Block{
		{Type: "text", Text: tr("We do not use advertising trackers on this site. When you write to us we keep your message to reply and to manage a project if one follows. We never sell or share your details.", "ما در این سایت ردیاب تبلیغاتی نداریم. وقتی برای ما می‌نویسید پیام شما را برای پاسخ و در صورت آغاز پروژه برای مدیریت آن نگه می‌داریم. اطلاعات شما هرگز فروخته یا به اشتراک گذاشته نمی‌شود.")},
	}}
	c.Pages = []Page{home, work, services, about, contact, privacy}
	return c
}
