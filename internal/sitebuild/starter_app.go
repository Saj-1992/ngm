package sitebuild

// starterApp is a complete product site for a trip-planning mobile app:
// features, pricing, support, changelog and privacy. The brand is fictional;
// all details are editable.
func starterApp() *Content {
	c := &Content{Site: Site{
		Title:   tr("Hamrah", "همراه"),
		Tagline: tr("The trip planner that works offline.", "برنامه‌ریز سفر که آفلاین هم کار می‌کند."),
		Footer:  tr("© Hamrah. Made for travellers.\nsupport@hamrah-app.example", "© همراه. ساخته‌شده برای مسافران.\nsupport@hamrah-app.example"),
		Accent:  "#5b3fd1",
	}}
	faq := []Item{
		it("Does Hamrah work without internet?", "آیا همراه بدون اینترنت کار می‌کند؟", "Yes. Maps, itineraries, tickets and notes are stored on your phone, so everything works in the mountains, on a plane or abroad without roaming.", "بله. نقشه‌ها، برنامه سفر، بلیت‌ها و یادداشت‌ها روی گوشی ذخیره می‌شوند و همه‌چیز در کوه، هواپیما یا خارج از کشور بدون رومینگ کار می‌کند."),
		it("Which devices are supported?", "کدام دستگاه‌ها پشتیبانی می‌شوند؟", "Android 8 and later, and iOS 15 and later. A web companion lets you view and print your plans from a computer.", "اندروید ۸ به بعد و iOS 15 به بعد. همراهِ وب هم برای مشاهده و چاپ برنامه‌ها از رایانه در دسترس است."),
		it("Is my data private?", "آیا داده‌های من خصوصی است؟", "Your plans stay on your device unless you turn on sync. Synced data is encrypted in transit and at rest, and we never sell it or show ads.", "برنامه‌های شما روی دستگاه می‌ماند مگر همگام‌سازی را روشن کنید. داده‌های همگام‌شده در انتقال و ذخیره رمزنگاری می‌شوند و هرگز فروخته نمی‌شوند و تبلیغی نیست."),
		it("Can I plan a trip with friends?", "می‌توانم سفر را با دوستان برنامه‌ریزی کنم؟", "Yes. Invite people by link; everyone sees the same plan, can add places and vote on options, and changes appear on all phones.", "بله. با لینک دعوت کنید؛ همه یک برنامه را می‌بینند، مکان اضافه می‌کنند و روی گزینه‌ها رأی می‌دهند و تغییرات روی همهٔ گوشی‌ها دیده می‌شود."),
		it("How do I cancel Plus?", "اشتراک پلاس را چطور لغو کنم؟", "Cancel any time from your app store subscription settings. You keep Plus features until the end of the paid period, and your plans are never deleted.", "هر زمان از تنظیمات اشتراک فروشگاه اپ لغو کنید. تا پایان دورهٔ پرداخت‌شده از امکانات پلاس برخوردارید و برنامه‌هایتان هرگز حذف نمی‌شود."),
	}
	home := Page{Slug: "", Title: tr("Home", "خانه"), Description: tr("Hamrah plans your trips, keeps tickets and maps offline, and lets friends plan together.", "همراه سفرهایتان را برنامه‌ریزی می‌کند، بلیت‌ها و نقشه‌ها را آفلاین نگه می‌دارد و به دوستان اجازه می‌دهد با هم برنامه بریزند."), Image: "hero-app.png", Blocks: []Block{
		{Type: "hero", Image: "hero-app.png", Heading: tr("Plan the trip. Forget the signal.", "سفر را برنامه بریز. آنتن را فراموش کن."), Text: tr("Hamrah turns scattered bookings, notes and maps into one clear itinerary that works offline, and keeps your travelling group on the same page.", "همراه رزروها، یادداشت‌ها و نقشه‌های پراکنده را به یک برنامه روشن تبدیل می‌کند که آفلاین کار می‌کند و گروه سفر را هماهنگ نگه می‌دارد."), Label: tr("See how it works", "ببینید چطور کار می‌کند"), Href: "page:features"},
		{Type: "stats", Items: []Item{
			it("500k+", "بیش از ۵۰۰ هزار", "travellers", "مسافر"),
			it("4.8", "۴٫۸", "average store rating", "میانگین امتیاز فروشگاه"),
			it("120", "۱۲۰", "countries with offline maps", "کشور با نقشهٔ آفلاین"),
		}},
		{Type: "features", Heading: tr("Everything for the road", "همه‌چیز برای مسیر"), Items: []Item{
			itImg("shot-1.png", "Offline maps", "نقشهٔ آفلاین", "Download a region once and navigate anywhere, with your saved places pinned.", "یک بار منطقه را دانلود کنید و هرجا بدون اینترنت مسیریابی کنید؛ مکان‌های ذخیره‌شده روی نقشه است."),
			itImg("shot-2.png", "Shared itineraries", "برنامهٔ مشترک", "Invite friends, vote on places and keep everyone's plan in sync.", "دوستان را دعوت کنید، به مکان‌ها رأی دهید و برنامهٔ همه را همگام نگه دارید."),
			itImg("shot-3.png", "Tickets and bookings", "بلیت و رزرو", "Forward confirmation emails and Hamrah files them on the right day.", "ایمیل‌های تأیید را فوروارد کنید تا همراه آن‌ها را در روز درست بگذارد."),
		}},
		{Type: "quote", Heading: tr("— Parisa, travel blogger", "— پریسا، وبلاگ‌نویس سفر"), Text: tr("We lost signal for three days in the Alborz and never lost the plan. Hamrah is the only app I trust on the road.", "سه روز در البرز آنتن نداشتیم و برنامه را هرگز گم نکردیم. همراه تنها اپی است که در سفر به آن اعتماد دارم.")},
		{Type: "faq", Heading: tr("Common questions", "پرسش‌های رایج"), Items: faq},
		{Type: "cta", Heading: tr("Start your next trip", "سفر بعدی‌تان را شروع کنید"), Text: tr("Free to start, no account needed.", "شروع رایگان، بدون نیاز به حساب."), Label: tr("Get the app", "دریافت اپ"), Href: "page:download"},
	}}
	features := Page{Slug: "features", Title: tr("Features", "امکانات"), Description: tr("Offline maps, shared itineraries, tickets and budgets in one app.", "نقشهٔ آفلاین، برنامهٔ مشترک، بلیت و بودجه در یک اپ."), Blocks: []Block{
		{Type: "hero", Heading: tr("Features", "امکانات"), Text: tr("Built around how people really travel: in groups, with patchy signal and plans that change.", "ساخته‌شده بر پایهٔ شیوهٔ واقعی سفر: گروهی، با آنتن ضعیف و برنامه‌هایی که تغییر می‌کنند.")},
		{Type: "features", Items: []Item{
			it("Day-by-day itinerary", "برنامهٔ روزبه‌روز", "Drag places into days, see travel times between them and spot days that are too full.", "مکان‌ها را به روزها بکشید، زمان رفت‌وآمد را ببینید و روزهای پرشده را تشخیص دهید."),
			it("Offline everything", "همه‌چیز آفلاین", "Maps, tickets, notes and your itinerary are saved on your phone.", "نقشه، بلیت، یادداشت و برنامه روی گوشی ذخیره می‌شود."),
			it("Group planning", "برنامه‌ریزی گروهی", "Invite by link, vote on options and see changes live on every phone.", "با لینک دعوت کنید، به گزینه‌ها رأی دهید و تغییرات را زنده روی همه گوشی‌ها ببینید."),
			it("Budget tracker", "پیگیر بودجه", "Log costs in any currency, split them fairly and see who owes what.", "هزینه‌ها را با هر ارز ثبت کنید، منصفانه تقسیم کنید و ببینید چه کسی چقدر بدهکار است."),
			it("Smart reminders", "یادآورهای هوشمند", "Check-in times, visa deadlines and pack lists, delivered when they matter.", "زمان پذیرش، مهلت ویزا و فهرست بسته‌بندی، درست وقتی لازم است."),
			it("Private by design", "خصوصی از پایه", "No ads and no selling data. Sync is optional and encrypted.", "بدون تبلیغ و بدون فروش داده. همگام‌سازی اختیاری و رمزنگاری‌شده است."),
		}},
		{Type: "steps", Heading: tr("From idea to boarding in three steps", "از ایده تا سوار شدن در سه گام"), Items: []Item{
			it("Collect", "جمع‌آوری", "Save places from anywhere and forward your bookings.", "مکان‌ها را از هرجا ذخیره کنید و رزروها را فوروارد کنید."),
			it("Shape", "شکل‌دهی", "Arrange days, share with friends and agree on a plan.", "روزها را بچینید، با دوستان به اشتراک بگذارید و توافق کنید."),
			it("Go", "حرکت", "Download for offline and travel without worrying about signal.", "برای آفلاین دانلود کنید و بدون نگرانی از آنتن سفر کنید."),
		}},
	}}
	pricing := Page{Slug: "pricing", Title: tr("Pricing", "تعرفه"), Description: tr("Hamrah is free to use. Plus adds unlimited offline maps and group tools.", "همراه رایگان است. پلاس نقشهٔ آفلاین نامحدود و ابزار گروهی اضافه می‌کند."), Blocks: []Block{
		{Type: "hero", Heading: tr("Simple pricing", "تعرفهٔ ساده"), Text: tr("Start free. Upgrade only if you travel a lot.", "رایگان شروع کنید. فقط اگر زیاد سفر می‌کنید ارتقا دهید.")},
		{Type: "pricing", Label: tr("Choose plan", "انتخاب طرح"), Items: []Item{
			{Title: tr("Free", "رایگان"), Text: tr("**0** — forever\n3 trips · 2 offline regions · basic itinerary", "**۰** — همیشگی\n۳ سفر · ۲ منطقهٔ آفلاین · برنامهٔ پایه"), Href: "page:download"},
			{Title: tr("Plus", "پلاس"), Text: tr("**4.99 USD** / month\nUnlimited trips and offline maps · group voting · budget tools", "**۴٫۹۹ دلار** / ماه\nسفر و نقشهٔ آفلاین نامحدود · رأی‌گیری گروهی · ابزار بودجه"), Href: "page:download"},
			{Title: tr("Family", "خانواده"), Text: tr("**7.99 USD** / month\nPlus for up to six people with a shared library", "**۷٫۹۹ دلار** / ماه\nپلاس برای تا شش نفر با کتابخانهٔ مشترک"), Href: "page:download"},
		}},
		{Type: "faq", Heading: tr("Billing", "پرداخت"), Items: faq[3:]},
	}}
	download := Page{Slug: "download", Title: tr("Download", "دانلود"), Description: tr("Get Hamrah for Android and iOS.", "همراه را برای اندروید و iOS دریافت کنید."), Blocks: []Block{
		{Type: "hero", Heading: tr("Get Hamrah", "دریافت همراه"), Text: tr("Available for Android 8+ and iOS 15+. About 40 MB.", "برای اندروید ۸ به بعد و iOS 15 به بعد. حدود ۴۰ مگابایت.")},
		{Type: "contact", Heading: tr("Install", "نصب"), Items: []Item{
			it("Android", "اندروید", "Search for “Hamrah” in your app store, or ask support for the direct APK.", "«همراه» را در فروشگاه اپ جست‌وجو کنید یا از پشتیبانی فایل APK بخواهید."),
			it("iOS", "iOS", "Search for “Hamrah” in the App Store.", "«همراه» را در اپ‌استور جست‌وجو کنید."),
			it("Web", "وب", "View and print itineraries from any browser after signing in.", "پس از ورود، برنامه‌ها را از هر مرورگر ببینید و چاپ کنید."),
		}},
	}}
	changelog := Page{Slug: "changelog", Title: tr("Changelog", "تغییرات"), Description: tr("What is new in Hamrah.", "تازه‌های همراه."), Blocks: []Block{
		{Type: "timeline", Items: []Item{
			it("3.4 — September 2026", "۳٫۴ — شهریور ۱۴۰۵", "Group voting, split-bill improvements and faster offline map downloads.", "رأی‌گیری گروهی، بهبود تقسیم هزینه و دانلود سریع‌تر نقشهٔ آفلاین."),
			it("3.3 — June 2026", "۳٫۳ — خرداد ۱۴۰۵", "Email forwarding for bookings and a new dark theme.", "فوروارد ایمیل برای رزروها و تم تاریک جدید."),
			it("3.2 — March 2026", "۳٫۲ — اسفند ۱۴۰۴", "Visa deadline reminders and 12 new offline regions.", "یادآور مهلت ویزا و ۱۲ منطقهٔ آفلاین جدید."),
		}},
	}}
	support := Page{Slug: "support", Title: tr("Support", "پشتیبانی"), Description: tr("Help and contact for Hamrah users.", "راهنما و تماس برای کاربران همراه."), Blocks: []Block{
		{Type: "hero", Heading: tr("Support", "پشتیبانی"), Text: tr("We answer every message, usually within one working day.", "به همهٔ پیام‌ها پاسخ می‌دهیم، معمولاً ظرف یک روز کاری.")},
		{Type: "contact", Items: []Item{
			it("Email", "ایمیل", "[support@hamrah-app.example](mailto:support@hamrah-app.example)", "[support@hamrah-app.example](mailto:support@hamrah-app.example)"),
			it("Press", "رسانه", "[press@hamrah-app.example](mailto:press@hamrah-app.example)", "[press@hamrah-app.example](mailto:press@hamrah-app.example)"),
			it("Hours", "ساعات پاسخ‌گویی", "Saturday–Thursday 9:00–18:00", "شنبه تا پنجشنبه ۹ تا ۱۸"),
		}},
		{Type: "faq", Heading: tr("Help", "راهنما"), Items: faq},
	}}
	privacy := Page{Slug: "privacy", Title: tr("Privacy", "حریم خصوصی"), Description: tr("How Hamrah treats your data.", "همراه با داده‌های شما چگونه رفتار می‌کند."), Blocks: []Block{
		{Type: "text", Heading: tr("Privacy policy", "سیاست حریم خصوصی"), Text: tr("Hamrah keeps your plans on your device. If you enable sync, your data is encrypted in transit and at rest and is used only to provide the service.\n\nWe do not sell data and we do not show ads. Anonymous crash reports can be switched off in settings. You can export or delete your account data at any time from the app or by writing to support@hamrah-app.example.", "همراه برنامه‌های شما را روی دستگاه نگه می‌دارد. اگر همگام‌سازی را روشن کنید، داده‌ها در انتقال و ذخیره رمزنگاری می‌شوند و فقط برای ارائهٔ خدمت استفاده می‌شوند.\n\nداده‌ای نمی‌فروشیم و تبلیغ نشان نمی‌دهیم. گزارش‌های ناشناس خرابی را می‌توان در تنظیمات خاموش کرد. هر زمان می‌توانید از داخل اپ یا با نوشتن به support@hamrah-app.example داده‌های حساب خود را خروجی بگیرید یا حذف کنید.")},
	}}
	c.Pages = []Page{home, features, pricing, download, changelog, support, privacy}
	return c
}
