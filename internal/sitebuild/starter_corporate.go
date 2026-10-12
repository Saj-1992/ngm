package sitebuild

func tr(en, fa string) L { return L{"en": en, "fa": fa} }

func it(tEn, tFa, xEn, xFa string) Item {
	return Item{Title: tr(tEn, tFa), Text: tr(xEn, xFa)}
}

func itImg(img, tEn, tFa, xEn, xFa string) Item {
	return Item{Image: img, Title: tr(tEn, tFa), Text: tr(xEn, xFa)}
}

// starterCorporate is a complete company website: a villa design, building
// and advisory practice. The brand is fictional; all details are editable.
func starterCorporate() *Content {
	c := &Content{Site: Site{
		Title:   tr("Noor Villa Advisory", "مشاوران ویلای نور"),
		Tagline: tr("Design, permits and construction oversight for private villas.", "طراحی، اخذ مجوز و نظارت بر ساخت ویلاهای شخصی."),
		Footer:  tr("© Noor Villa Advisory. All rights reserved.\nPhone: +98 21 5550 1200 · info@noor-villa.example", "© مشاوران ویلای نور. تمامی حقوق محفوظ است.\nتلفن: ۰۲۱-۵۵۵۰۱۲۰۰ · info@noor-villa.example"),
		Accent:  "#1f5f8b",
	}}
	faq := Block{Type: "faq", Heading: tr("Frequently asked questions", "پرسش‌های پرتکرار"), Items: []Item{
		it("How long does a villa project take?", "یک پروژهٔ ویلا چقدر زمان می‌برد؟", "A typical 300 m² villa needs about 2 months for concept and drawings, 1–2 months for permits, and 10–14 months of construction. We give a written schedule before you commit.", "یک ویلای ۳۰۰ متری معمولاً حدود ۲ ماه برای طرح اولیه و نقشه‌ها، ۱ تا ۲ ماه برای مجوزها و ۱۰ تا ۱۴ ماه برای ساخت زمان می‌خواهد. پیش از تعهد، برنامهٔ زمانی مکتوب ارائه می‌کنیم."),
		it("Can you review land before we buy it?", "پیش از خرید زمین می‌توانید آن را بررسی کنید؟", "Yes. Our pre-purchase review covers zoning and density, access, soil and slope, utilities and the legal status of the plot, so you know the real cost of the land before signing.", "بله. بررسی پیش از خرید ما شامل کاربری و تراکم، دسترسی، خاک و شیب، انشعابات و وضعیت حقوقی قطعه است تا پیش از امضا هزینهٔ واقعی زمین را بدانید."),
		it("Do you also build, or only advise?", "خودتان هم می‌سازید یا فقط مشاوره می‌دهید؟", "We design and supervise. Construction is carried out by vetted contractors that you choose through a transparent tender, so there is no conflict of interest in our advice.", "ما طراحی و نظارت می‌کنیم. ساخت را پیمانکاران تأییدشده انجام می‌دهند که شما از طریق مناقصهٔ شفاف انتخاب می‌کنید؛ به این ترتیب در مشاورهٔ ما تضاد منافعی نیست."),
		it("How are your fees structured?", "هزینه‌های شما چگونه محاسبه می‌شود؟", "Design is a fixed fee agreed up front. Supervision is a monthly fee for the length of the build. We never take commissions from suppliers.", "طراحی با مبلغ ثابتِ توافق‌شده از ابتدا است. نظارت به‌صورت ماهانه و تا پایان ساخت محاسبه می‌شود. ما از تأمین‌کنندگان هیچ کمیسیونی دریافت نمی‌کنیم."),
		it("Do you work outside the city?", "خارج از شهر هم کار می‌کنید؟", "Yes. Most of our villas are on the coast and in the hills. Our engineers visit the site on a fixed weekly schedule and report with photos and written notes.", "بله. بیشتر ویلاهای ما در ساحل و ییلاق هستند. مهندسان ما طبق برنامهٔ ثابت هفتگی از کارگاه بازدید می‌کنند و با عکس و گزارش مکتوب اطلاع می‌دهند."),
	}}
	home := Page{Slug: "", Title: tr("Home", "خانه"), Description: tr("Villa design, permits and construction supervision by a senior team of architects and engineers.", "طراحی ویلا، اخذ مجوز و نظارت بر ساخت توسط تیمی باتجربه از معماران و مهندسان."), Image: "hero-villa.png", Blocks: []Block{
		{Type: "hero", Image: "hero-villa.png", Heading: tr("Your villa, designed and built with care", "ویلای شما، با دقت طراحی و ساخته می‌شود"), Text: tr("Noor Villa Advisory guides private clients from choosing a plot to handing over the keys: architecture, engineering, permits and independent site supervision under one roof.", "مشاوران ویلای نور مشتریان خصوصی را از انتخاب زمین تا تحویل کلید همراهی می‌کند: معماری، مهندسی، مجوزها و نظارت مستقل بر کارگاه در یک مجموعه."), Label: tr("Book a consultation", "رزرو مشاوره"), Href: "page:contact"},
		{Type: "stats", Items: []Item{
			it("120+", "بیش از ۱۲۰", "villas delivered", "ویلای تحویل‌شده"),
			it("14", "۱۴", "years of practice", "سال سابقه"),
			it("22", "۲۲", "architects and engineers", "معمار و مهندس"),
			it("96%", "۹۶٪", "clients who recommend us", "مشتری که ما را توصیه می‌کنند"),
		}},
		{Type: "features", Heading: tr("What we do", "چه می‌کنیم"), Items: []Item{
			it("Architecture and interiors", "معماری و دکوراسیون داخلی", "Concept, detailed drawings and interiors shaped around how your family lives, the climate and the view.", "طرح اولیه، نقشه‌های اجرایی و فضای داخلی بر پایهٔ سبک زندگی خانواده، اقلیم و چشم‌انداز."),
			it("Permits and compliance", "مجوز و انطباق", "We prepare and follow every municipal and structural approval so nothing stalls on paperwork.", "تمام تأییدیه‌های شهرداری و سازه را آماده و پیگیری می‌کنیم تا کار پشت کاغذبازی نماند."),
			it("Independent supervision", "نظارت مستقل", "Weekly site visits, quality checks against the drawings and honest reports on cost and schedule.", "بازدید هفتگی، کنترل کیفیت نسبت به نقشه‌ها و گزارش صادقانه از هزینه و زمان."),
			it("Land and feasibility", "زمین و امکان‌سنجی", "Independent review of a plot before purchase: zoning, soil, access, utilities and risk.", "بررسی مستقل زمین پیش از خرید: کاربری، خاک، دسترسی، انشعابات و ریسک."),
		}},
		{Type: "gallery", Heading: tr("Recent projects", "پروژه‌های اخیر"), Items: []Item{
			itImg("project-1.png", "Hillside villa, Chalus", "ویلای دامنه‌ای، چالوس", "420 m² on three terraces with passive cooling and a green roof.", "۴۲۰ متر در سه تراس، با خنک‌سازی غیرفعال و بام سبز."),
			itImg("project-2.png", "Courtyard house, Shiraz", "خانهٔ حیاط‌دار، شیراز", "A contemporary take on the traditional courtyard, built in local brick.", "برداشتی امروزی از حیاط سنتی، با آجر محلی."),
			itImg("project-3.png", "Sea-view villa, Kish", "ویلای رو به دریا، کیش", "Wind-aware massing, deep shade and a hurricane-grade envelope.", "حجم‌بندی همساز با باد، سایهٔ عمیق و پوستهٔ مقاوم."),
		}},
		{Type: "quote", Heading: tr("— Client, Chalus hillside villa", "— مشتری، ویلای دامنه‌ای چالوس"), Text: tr("They told us what not to buy as often as what to build. The supervision reports saved us from two expensive mistakes.", "به همان اندازه که می‌گفتند چه بسازیم، می‌گفتند چه نخریم. گزارش‌های نظارت ما را از دو اشتباه پرهزینه نجات داد.")},
		{Type: "cta", Heading: tr("Planning a villa?", "ویلایی در نظر دارید؟"), Text: tr("Tell us about the plot and your plans. The first call is free and we reply within one working day.", "دربارهٔ زمین و برنامه‌تان بگویید. تماس اول رایگان است و ظرف یک روز کاری پاسخ می‌دهیم."), Label: tr("Contact us", "تماس با ما"), Href: "page:contact"},
	}}
	services := Page{Slug: "services", Title: tr("Services", "خدمات"), Description: tr("Architecture, permits, supervision and land feasibility for private villas.", "معماری، مجوز، نظارت و امکان‌سنجی زمین برای ویلاهای شخصی."), Blocks: []Block{
		{Type: "hero", Heading: tr("Services", "خدمات"), Text: tr("Clear scopes, fixed fees and one accountable team from first sketch to handover.", "دامنهٔ کار روشن، دستمزد ثابت و یک تیم پاسخگو از اولین طرح تا تحویل.")},
		{Type: "steps", Heading: tr("How a project runs", "پروژه چگونه پیش می‌رود"), Items: []Item{
			it("Discovery", "شناخت", "We listen, visit the plot and write a short brief with budget, schedule and risks.", "گوش می‌دهیم، از زمین بازدید می‌کنیم و خلاصه‌ای کوتاه از بودجه، زمان و ریسک‌ها می‌نویسیم."),
			it("Concept", "طرح اولیه", "Two or three design directions with plans, sections and a first cost range.", "دو یا سه جهت طراحی همراه با پلان، برش و برآورد اولیهٔ هزینه."),
			it("Drawings and permits", "نقشه و مجوز", "Detailed architectural and structural drawings, submitted and followed to approval.", "نقشه‌های معماری و سازهٔ تفصیلی که تا اخذ تأییدیه ارسال و پیگیری می‌شوند."),
			it("Tender", "مناقصه", "We prepare the bill of quantities and compare at least three contractors openly.", "صورت‌ریز متره را آماده می‌کنیم و دست‌کم سه پیمانکار را شفاف مقایسه می‌کنیم."),
			it("Supervision", "نظارت", "Weekly visits, photo reports, material approvals and payment certification.", "بازدید هفتگی، گزارش تصویری، تأیید مصالح و تأیید صورت‌وضعیت‌ها."),
			it("Handover", "تحویل", "Final inspection, snag list, as-built drawings and a maintenance guide.", "بازرسی نهایی، فهرست رفع نقص، نقشه‌های چون‌ساخت و راهنمای نگهداری."),
		}},
		{Type: "features", Heading: tr("Also available", "خدمات تکمیلی"), Items: []Item{
			it("Landscape and pools", "محوطه‌سازی و استخر", "Planting, irrigation, lighting and pool engineering designed with the house.", "کاشت، آبیاری، روشنایی و مهندسی استخر هماهنگ با ساختمان."),
			it("Energy and comfort", "انرژی و آسایش", "Insulation, shading and heating strategies that cut running costs.", "راهکارهای عایق، سایه‌بان و گرمایش که هزینهٔ بهره‌برداری را کم می‌کند."),
			it("Renovation", "بازسازی", "Surveys, structural checks and phased renovation of existing villas.", "برداشت، کنترل سازه و بازسازی مرحله‌ای ویلاهای موجود."),
		}},
		faq,
	}}
	projects := Page{Slug: "projects", Title: tr("Projects", "پروژه‌ها"), Description: tr("Selected villas designed and supervised by Noor Villa Advisory.", "ویلاهای منتخب طراحی و نظارت‌شده توسط مشاوران ویلای نور."), Blocks: []Block{
		{Type: "hero", Heading: tr("Selected projects", "پروژه‌های منتخب"), Text: tr("A few of the villas we have designed and supervised across the north and south of the country.", "چند ویلا از ویلاهایی که در شمال و جنوب کشور طراحی و نظارت کرده‌ایم.")},
		{Type: "gallery", Items: []Item{
			itImg("project-1.png", "Hillside villa, Chalus — 2024", "ویلای دامنه‌ای، چالوس — ۱۴۰۳", "Three terraces follow the slope; timber screens control summer sun; rainwater is collected for the garden.", "سه تراس شیب زمین را دنبال می‌کنند؛ پرده‌های چوبی آفتاب تابستان را مهار می‌کنند؛ آب باران برای باغ ذخیره می‌شود."),
			itImg("project-2.png", "Courtyard house, Shiraz — 2023", "خانهٔ حیاط‌دار، شیراز — ۱۴۰۲", "Rooms open onto a shaded courtyard with a pool of water, cooling the house without machinery.", "اتاق‌ها به حیاطی سایه‌دار با آبنما باز می‌شوند و خانه را بدون دستگاه خنک می‌کنند."),
			itImg("project-3.png", "Sea-view villa, Kish — 2023", "ویلای رو به دریا، کیش — ۱۴۰۲", "Deep verandas, reflective finishes and storm-rated glazing for a exposed coastal plot.", "ایوان‌های عمیق، پوشش‌های بازتابنده و شیشهٔ مقاوم در برابر طوفان برای زمینی ساحلی."),
		}},
		{Type: "text", Heading: tr("Our approach to every project", "رویکرد ما در هر پروژه"), Text: tr("Every villa starts from the same three questions: how will the family live here, what does the climate ask of the building, and what budget will make the result last? The answers, not a fixed style, shape the design.", "هر ویلا از همین سه پرسش آغاز می‌شود: خانواده چگونه در آن زندگی می‌کند، اقلیم از ساختمان چه می‌خواهد، و چه بودجه‌ای نتیجه را ماندگار می‌کند؟ پاسخ این پرسش‌ها، نه یک سبک ثابت، طراحی را شکل می‌دهد.")},
	}}
	about := Page{Slug: "about", Title: tr("About", "درباره ما"), Description: tr("A senior team of architects and engineers advising on private villas since 2011.", "تیمی باتجربه از معماران و مهندسان که از سال ۱۳۹۰ در زمینهٔ ویلاهای شخصی مشاوره می‌دهد."), Blocks: []Block{
		{Type: "hero", Heading: tr("About Noor Villa Advisory", "دربارهٔ مشاوران ویلای نور"), Text: tr("We are architects and engineers who believe a private home deserves the same rigour as a public building.", "ما معمار و مهندسانی هستیم که باور داریم خانهٔ شخصی هم باید به اندازهٔ یک ساختمان عمومی با دقت ساخته شود.")},
		{Type: "text", Text: tr("Noor started in 2011 as two architects advising friends on land and permits. Clients kept asking for the same thing: someone independent, on their side, who would read the contract and visit the site. That became our practice.\n\nToday 22 people work from our Tehran office and a regional office on the Caspian coast. We take on a limited number of villas each year so every project has a senior partner involved.", "نور در سال ۱۳۹۰ با دو معمار آغاز شد که به دوستان در زمینهٔ زمین و مجوز مشاوره می‌دادند. مشتریان همیشه همین را می‌خواستند: کسی مستقل و در کنار خودشان که قرارداد را بخواند و از کارگاه بازدید کند. همین شد کار ما.\n\nامروز ۲۲ نفر در دفتر تهران و یک دفتر منطقه‌ای در ساحل خزر کار می‌کنند. هر سال تعداد محدودی ویلا می‌پذیریم تا در هر پروژه یک شریک ارشد حضور داشته باشد.")},
		{Type: "timeline", Heading: tr("Milestones", "نقاط عطف"), Items: []Item{
			it("2011", "۱۳۹۰", "Founded in Tehran by two architects.", "تأسیس در تهران توسط دو معمار."),
			it("2015", "۱۳۹۴", "First regional office opened on the Caspian coast.", "افتتاح اولین دفتر منطقه‌ای در ساحل خزر."),
			it("2019", "۱۳۹۸", "Independent supervision service launched.", "راه‌اندازی خدمت نظارت مستقل."),
			it("2024", "۱۴۰۳", "100th villa handed over.", "تحویل ویلای صدم."),
		}},
		{Type: "team", Heading: tr("Leadership", "مدیران"), Items: []Item{
			it("Sara Nouri", "سارا نوری", "Principal architect. Leads design and client relations.", "معمار ارشد. مسئول طراحی و ارتباط با مشتریان."),
			it("Kaveh Rostami", "کاوه رستمی", "Structural engineer. Leads engineering and permits.", "مهندس سازه. مسئول مهندسی و مجوزها."),
			it("Leila Ahmadi", "لیلا احمدی", "Head of supervision. Runs site teams and reporting.", "مسئول نظارت. مدیریت تیم‌های کارگاهی و گزارش‌دهی."),
		}},
	}}
	contact := Page{Slug: "contact", Title: tr("Contact", "تماس"), Description: tr("Book a free first consultation with Noor Villa Advisory.", "یک مشاورهٔ اولیهٔ رایگان با مشاوران ویلای نور رزرو کنید."), Blocks: []Block{
		{Type: "hero", Heading: tr("Contact", "تماس با ما"), Text: tr("Tell us about your plot and plans. We reply within one working day.", "دربارهٔ زمین و برنامه‌تان بگویید. ظرف یک روز کاری پاسخ می‌دهیم.")},
		{Type: "contact", Heading: tr("Our offices", "دفاتر ما"), Items: []Item{
			it("Tehran", "تهران", "No. 14, Valiasr Ave, 3rd floor", "خیابان ولیعصر، پلاک ۱۴، طبقهٔ سوم"),
			it("Caspian office", "دفتر خزر", "Chalus, Imam Khomeini Blvd, No. 62", "چالوس، بلوار امام خمینی، پلاک ۶۲"),
			it("Phone", "تلفن", "[+98 21 5550 1200](tel:+982155501200)", "[۰۲۱-۵۵۵۰۱۲۰۰](tel:+982155501200)"),
			it("Email", "ایمیل", "[info@noor-villa.example](mailto:info@noor-villa.example)", "[info@noor-villa.example](mailto:info@noor-villa.example)"),
			it("Hours", "ساعات کاری", "Saturday–Wednesday 9:00–17:00, Thursday 9:00–13:00", "شنبه تا چهارشنبه ۹ تا ۱۷، پنجشنبه ۹ تا ۱۳"),
		}},
		{Type: "text", Heading: tr("Before you call", "پیش از تماس"), Text: tr("It helps to have the plot's location, approximate size and your rough budget at hand. If you already have a survey or a title deed, send us a copy by email and we will review it before we speak.", "بهتر است موقعیت زمین، متراژ تقریبی و بودجهٔ کلی را در دسترس داشته باشید. اگر نقشهٔ برداری یا سند دارید، رونوشت آن را ایمیل کنید تا پیش از گفت‌وگو بررسی کنیم.")},
	}}
	privacy := Page{Slug: "privacy", Title: tr("Privacy", "حریم خصوصی"), Description: tr("How Noor Villa Advisory handles personal information.", "نحوهٔ برخورد مشاوران ویلای نور با اطلاعات شخصی."), Blocks: []Block{
		{Type: "text", Heading: tr("Privacy policy", "سیاست حریم خصوصی"), Text: tr("We collect only what we need to respond to you: your name, contact details and the information you share about your project. We use it to answer your enquiry and, if you become a client, to run your project.\n\nWe do not sell personal information. We share it only with consultants and authorities involved in your project, and only with your agreement. This website does not use advertising trackers.\n\nYou can ask us at any time to see, correct or delete the information we hold about you by writing to info@noor-villa.example.", "ما فقط اطلاعاتی را جمع می‌کنیم که برای پاسخ به شما لازم است: نام، اطلاعات تماس و آنچه دربارهٔ پروژه‌تان می‌گویید. از آن برای پاسخ به درخواست شما و در صورت همکاری، اجرای پروژه استفاده می‌کنیم.\n\nاطلاعات شخصی را نمی‌فروشیم. فقط با مشاوران و مراجعی که در پروژهٔ شما نقش دارند و فقط با موافقت شما به اشتراک می‌گذاریم. این وب‌سایت از ردیاب‌های تبلیغاتی استفاده نمی‌کند.\n\nهر زمان می‌توانید با ایمیل به info@noor-villa.example درخواست مشاهده، اصلاح یا حذف اطلاعاتتان را بدهید.")},
	}}
	faqPage := Page{Slug: "faq", Title: tr("FAQ", "پرسش‌های رایج"), Description: tr("Answers to common questions about villa projects.", "پاسخ پرسش‌های رایج دربارهٔ پروژه‌های ویلا."), Blocks: []Block{
		{Type: "hero", Heading: tr("Frequently asked questions", "پرسش‌های پرتکرار"), Text: tr("Short answers about schedules, fees and how we work. Cannot find yours? Write to us.", "پاسخ کوتاه دربارهٔ زمان‌بندی، هزینه و شیوهٔ کار ما. پاسخ پرسش خود را نیافتید؟ برایمان بنویسید.")},
		faq,
		{Type: "cta", Heading: tr("Still have a question?", "هنوز پرسشی دارید؟"), Label: tr("Contact us", "تماس با ما"), Href: "page:contact"},
	}}
	c.Pages = []Page{home, services, projects, about, faqPage, contact, privacy}
	return c
}
