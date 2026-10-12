package sitebuild

func post(slug, date, img, tEn, tFa, dEn, dFa, bEn, bFa string) Page {
	return Page{Slug: slug, Kind: "post", Date: date, Image: img, Title: tr(tEn, tFa), Description: tr(dEn, dFa),
		Blocks: []Block{{Type: "text", Text: tr(bEn, bFa)}}}
}

// starterBlog is a complete magazine-style blog about homes, gardens and
// slow living. The brand is fictional; all details are editable.
func starterBlog() *Content {
	c := &Content{Site: Site{
		Title:   tr("Sarv Journal", "مجلهٔ سرو"),
		Tagline: tr("Notes on homes, gardens and slower living.", "یادداشت‌هایی دربارهٔ خانه، باغ و زندگی آرام‌تر."),
		Footer:  tr("© Sarv Journal. Independent writing about the places we live in.", "© مجلهٔ سرو. نوشته‌هایی مستقل دربارهٔ جاهایی که در آن زندگی می‌کنیم."),
		Accent:  "#3b6b4a",
	}}
	home := Page{Slug: "", Title: tr("Home", "خانه"), Description: tr("Independent writing about homes, gardens, materials and slower living.", "نوشته‌های مستقل دربارهٔ خانه، باغ، مصالح و زندگی آرام‌تر."), Blocks: []Block{
		{Type: "hero", Image: "cover-1.png", Heading: tr("Writing for people who love their homes", "نوشته‌هایی برای کسانی که خانه‌شان را دوست دارند"), Text: tr("Sarv Journal publishes unhurried essays on architecture, gardens, materials and the small rituals that make a house feel like home. New pieces every week.", "مجلهٔ سرو جستارهای بی‌شتاب دربارهٔ معماری، باغ، مصالح و آیین‌های کوچکی منتشر می‌کند که یک ساختمان را خانه می‌کند. هر هفته نوشتهٔ تازه."), Label: tr("About the journal", "دربارهٔ مجله"), Href: "page:about"},
		{Type: "posts", Heading: tr("Latest writing", "تازه‌ترین نوشته‌ها")},
		{Type: "cta", Heading: tr("Write to us", "برایمان بنویسید"), Text: tr("Have a story about a house, a garden or a craft? We read every message.", "داستانی دربارهٔ یک خانه، باغ یا هنر دستی دارید؟ تک‌تک پیام‌ها را می‌خوانیم."), Label: tr("Contact the editors", "تماس با سردبیران"), Href: "page:contact"},
	}}
	posts := []Page{
		post("courtyard-houses", "2026-09-28", "cover-3.png",
			"Why courtyard houses keep coming back", "چرا خانه‌های حیاط‌دار دوباره برمی‌گردند",
			"The old courtyard plan solves problems that modern houses still struggle with.", "پلان حیاط‌دار قدیمی مشکلاتی را حل می‌کند که خانه‌های امروزی هنوز با آن‌ها درگیرند.",
			"Walk through any old town in central Iran and you will find the same plan repeated: rooms facing inward onto a courtyard, a pool at its centre, a tree for shade. It is not nostalgia that brings the plan back. It is physics.\n\nA courtyard is a climate machine. At night it fills with cool air; by day its walls shade each other and the water cools what passes over it. The rooms around it borrow light and ventilation without looking onto the street.\n\nModern architects are rediscovering this, adding glass and thin walls but keeping the idea: a protected outdoor room that belongs to the family. If you are planning a house, ask early what your courtyard will be.",
			"در هر شهر قدیمی مرکز ایران بگردید همین پلان را می‌بینید: اتاق‌هایی رو به حیاط، حوضی در مرکز و درختی برای سایه. این پلان از سر نوستالژی بازنمی‌گردد؛ از سر فیزیک بازمی‌گردد.\n\nحیاط یک ماشین اقلیمی است. شب‌ها پر از هوای خنک می‌شود؛ روزها دیوارهایش بر یکدیگر سایه می‌اندازند و آب، هوایی را که از رویش می‌گذرد خنک می‌کند. اتاق‌های اطراف بدون رو کردن به کوچه، نور و تهویه می‌گیرند.\n\nمعماران امروز دوباره این را کشف می‌کنند: شیشه و دیوارهای نازک‌تر، اما همان ایده، یعنی اتاقی بیرونیِ محافظت‌شده که متعلق به خانواده است. اگر خانه می‌سازید، زود بپرسید حیاط شما چه خواهد بود."),
		post("a-garden-in-small-spaces", "2026-09-14", "cover-4.png",
			"A real garden in a very small space", "باغی واقعی در فضایی بسیار کوچک",
			"Six ideas that work on balconies, rooftops and narrow plots.", "شش ایده که روی بالکن، پشت‌بام و زمین‌های باریک جواب می‌دهد.",
			"You do not need a hectare to have a garden. You need light, a little soil depth, and the patience to start small.\n\nStart with one anchor: a lemon tree in a big pot, a jasmine on a wire, a row of herbs along a rail. Choose plants that suit your light, not the ones in pictures. Water deeply but rarely so roots go down.\n\nThen add layers: something tall, something trailing, something that smells. A small bench changes everything because it gives you a reason to sit and look. A garden is mostly time spent in it.",
			"برای داشتن باغ به یک هکتار زمین نیاز ندارید. نور، کمی عمق خاک و صبر برای شروع کوچک کافی است.\n\nبا یک تکیه‌گاه شروع کنید: یک درخت لیمو در گلدان بزرگ، یک یاس روی سیم، ردیفی سبزی خوردن کنار نرده. گیاهانی را برگزینید که به نور شما می‌خورند، نه آن‌هایی که در عکس‌ها هستند. عمیق اما کم‌دفعات آب بدهید تا ریشه پایین برود.\n\nبعد لایه اضافه کنید: چیزی بلند، چیزی آویزان، چیزی خوشبو. یک نیمکت کوچک همه‌چیز را عوض می‌کند چون دلیلی برای نشستن و نگاه کردن می‌دهد. باغ بیشتر زمانی است که در آن می‌گذرانید."),
		post("brick-and-time", "2026-08-30", "cover-6.png",
			"Brick and time", "آجر و زمان",
			"What fired clay teaches us about materials that age well.", "گِل پخته دربارهٔ مصالحی که خوب پیر می‌شوند چه می‌آموزد.",
			"Some materials look best on the day they are installed and decline from there. Brick is the opposite. It darkens, gathers moss in the shade, and records every season on its face.\n\nGood brickwork depends on the quiet decisions: the bond pattern, the width of the joint, the way water is thrown clear of the wall by a small overhang. None of it is expensive; all of it is attention.\n\nWhen you choose finishes, ask how they will look in twenty years. A house that ages gracefully is one that was designed for it.",
			"برخی مصالح در روز نصب بهترین ظاهر را دارند و از آن پس افت می‌کنند. آجر برعکس است. تیره‌تر می‌شود، در سایه خزه می‌بندد و هر فصل را روی صورتش ثبت می‌کند.\n\nآجرکاریِ خوب به تصمیم‌های آرام بستگی دارد: الگوی چیدمان، عرض بند و اینکه چطور یک پیش‌آمدگی کوچک آب را از دیوار دور می‌اندازد. هیچ‌کدام گران نیست؛ همه‌اش توجه است.\n\nوقتی نما انتخاب می‌کنید بپرسید بیست سال دیگر چه شکلی خواهد بود. خانه‌ای که زیبا پیر می‌شود، برای آن طراحی شده است."),
		post("light-in-the-morning", "2026-08-12", "cover-1.png",
			"Designing for morning light", "طراحی برای نور صبح",
			"Where to put the kitchen, the bed and the breakfast table.", "آشپزخانه، تخت و میز صبحانه را کجا بگذاریم.",
			"Most of us meet the house at its worst: tired, hurried, in the first hour. Yet we rarely design for that hour.\n\nPut the breakfast table where the sun arrives first. Let the kitchen face east so it warms before you cook. Keep bedrooms cooler and darker, with a window that lets in a little dawn rather than all of it.\n\nA house that greets you kindly in the morning changes the day. It costs nothing to decide this early, and a great deal to fix later.",
			"بیشتر ما خانه را در بدترین حالتش می‌بینیم: خسته و شتابان، در ساعت اول. با این حال کمتر برای آن ساعت طراحی می‌کنیم.\n\nمیز صبحانه را جایی بگذارید که آفتاب زودتر می‌رسد. آشپزخانه را رو به شرق بسازید تا پیش از پخت‌وپز گرم شود. اتاق‌خواب‌ها خنک‌تر و تاریک‌تر باشند، با پنجره‌ای که کمی از سپیده را بیاورد نه همه‌اش را.\n\nخانه‌ای که صبح مهربانانه به شما سلام می‌کند، روز را عوض می‌کند. تصمیم زودهنگامش هزینه‌ای ندارد و اصلاح بعدی‌اش بسیار گران است."),
		post("renovating-slowly", "2026-07-26", "cover-5.png",
			"Renovating slowly", "بازسازی آهسته",
			"Why phasing a renovation often gives a better house.", "چرا مرحله‌ای کردن بازسازی اغلب خانهٔ بهتری می‌دهد.",
			"The idea of doing everything at once is attractive and usually wrong. You do not yet know how you will use the house.\n\nLive in it for a season. Notice where you actually sit, which rooms stay empty, where the light fails. Then start with the things that fix real problems: water, wiring, insulation. Leave the decoration for last.\n\nPhasing also spreads cost and lets you correct course. The best renovated houses we have seen were never finished in a weekend.",
			"ایدهٔ انجام همه‌چیز با هم جذاب است و معمولاً نادرست. هنوز نمی‌دانید از خانه چطور استفاده خواهید کرد.\n\nیک فصل در آن زندگی کنید. ببینید واقعاً کجا می‌نشینید، کدام اتاق‌ها خالی می‌ماند و نور کجا کم است. بعد با چیزهایی شروع کنید که مشکل واقعی را حل می‌کنند: آب، برق، عایق. تزئین را آخر بگذارید.\n\nمرحله‌ای‌کردن هزینه را پخش می‌کند و امکان اصلاح مسیر می‌دهد. بهترین خانه‌های بازسازی‌شده‌ای که دیده‌ایم هرگز در یک آخر هفته تمام نشده بودند."),
		post("water-in-the-garden", "2026-07-05", "cover-2.png",
			"Water in the garden", "آب در باغ",
			"A small channel, a basin or a bowl can change how a garden feels.", "یک جوی کوچک، یک حوض یا یک کاسه می‌تواند حال‌وهوای باغ را عوض کند.",
			"The Persian garden was built around water: a channel that divides the space and a pool that doubles the sky. You can borrow the idea at any scale.\n\nA shallow bowl for birds brings movement and sound. A narrow channel along a path cools the air and gives the eye a line to follow. Even a still basin, kept clean, gives the garden a centre.\n\nChoose the place first, then the vessel. Water works best where you will pass it every day.",
			"باغ ایرانی دور آب ساخته شد: جویی که فضا را تقسیم می‌کند و حوضی که آسمان را دوبرابر می‌کند. این ایده را در هر مقیاسی می‌توان به کار برد.\n\nیک کاسهٔ کم‌عمق برای پرندگان، حرکت و صدا می‌آورد. جوی باریکی کنار مسیر هوا را خنک می‌کند و به چشم خطی برای دنبال کردن می‌دهد. حتی یک حوض ساکن و تمیز به باغ مرکز می‌دهد.\n\nاول جا را انتخاب کنید، بعد ظرف را. آب در جایی بهتر کار می‌کند که هر روز از کنارش بگذرید."),
	}
	about := Page{Slug: "about", Title: tr("About", "درباره"), Description: tr("Who writes Sarv Journal and why.", "چه کسانی برای مجلهٔ سرو می‌نویسند و چرا."), Blocks: []Block{
		{Type: "hero", Heading: tr("About Sarv Journal", "دربارهٔ مجلهٔ سرو"), Text: tr("An independent journal, written by architects, gardeners and makers who like to take their time.", "مجله‌ای مستقل، نوشتهٔ معماران، باغبانان و سازندگانی که دوست دارند فرصت بگذارند.")},
		{Type: "text", Text: tr("Sarv began in 2022 as a notebook shared between friends who kept sending each other photographs of doors, walls and trees. We wanted somewhere to put the thoughts that did not fit on social media.\n\nWe publish one or two essays a week. There are no advertorials and no sponsored posts. If we recommend something, it is because we use it.", "سرو در سال ۱۴۰۱ به‌شکل یک دفترچهٔ مشترک میان دوستانی آغاز شد که مدام عکس در، دیوار و درخت برای هم می‌فرستادند. جایی می‌خواستیم برای فکرهایی که در شبکه‌های اجتماعی جا نمی‌شد.\n\nهفته‌ای یک یا دو جستار منتشر می‌کنیم. آگهی‌نما و نوشتهٔ حمایت‌شده نداریم. اگر چیزی را توصیه کنیم، به این دلیل است که خودمان از آن استفاده می‌کنیم.")},
		{Type: "team", Heading: tr("Editors", "سردبیران"), Items: []Item{
			it("Maryam Karimi", "مریم کریمی", "Editor-in-chief. Architect and writer.", "سردبیر. معمار و نویسنده."),
			it("Omid Farhadi", "امید فرهادی", "Garden editor. Landscape designer.", "سردبیر باغ. طراح منظر."),
			it("Nasim Tavakoli", "نسیم توکلی", "Materials editor. Craftsperson.", "سردبیر مصالح. صنعتگر."),
		}},
	}}
	contact := Page{Slug: "contact", Title: tr("Contact", "تماس"), Description: tr("Write to the editors of Sarv Journal.", "به سردبیران مجلهٔ سرو بنویسید."), Blocks: []Block{
		{Type: "text", Text: tr("We read everything. Send pitches, corrections or a note about a house you love.", "همه‌چیز را می‌خوانیم. پیشنهاد نوشته، اصلاحیه یا یادداشتی دربارهٔ خانه‌ای که دوستش دارید بفرستید.")},
		{Type: "contact", Items: []Item{
			it("Editors", "سردبیران", "[editors@sarv-journal.example](mailto:editors@sarv-journal.example)", "[editors@sarv-journal.example](mailto:editors@sarv-journal.example)"),
			it("Pitches", "پیشنهاد نوشته", "Send 3–4 sentences and a link to previous work. We answer within a week.", "سه تا چهار جمله و پیوندی به کارهای قبلی بفرستید. ظرف یک هفته پاسخ می‌دهیم."),
			it("Corrections", "اصلاحیه", "If we got something wrong, tell us. We fix it and note the change.", "اگر جایی اشتباه کرده‌ایم، بگویید. اصلاح می‌کنیم و تغییر را یادداشت می‌کنیم."),
		}},
	}}
	privacy := Page{Slug: "privacy", Title: tr("Privacy", "حریم خصوصی"), Blocks: []Block{
		{Type: "text", Text: tr("This site does not use advertising trackers or third-party analytics. Server logs record request time, path and a truncated address for security and capacity planning, and are kept for 30 days. If you email us, we keep your message only as long as needed to reply.", "این سایت از ردیاب تبلیغاتی یا تحلیل‌گر شخص ثالث استفاده نمی‌کند. لاگ‌های سرور زمان درخواست، مسیر و نشانی کوتاه‌شده را برای امنیت و برنامه‌ریزی ظرفیت ثبت می‌کنند و ۳۰ روز نگه داشته می‌شوند. اگر ایمیل بزنید، پیام شما فقط تا زمان لازم برای پاسخ نگه داشته می‌شود.")},
	}}
	c.Pages = append([]Page{home}, posts...)
	c.Pages = append(c.Pages, about, contact, privacy)
	return c
}
