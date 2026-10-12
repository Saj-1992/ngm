package sitebuild

// Starter returns complete, coherent starting content for a template (English
// and Persian). The four templates (corporate, blog, portfolio, app_showcase)
// are full branded websites with their own artwork (see StarterMedia).
// Identities are fictional and generic; no real businesses, people, reviews or
// contact details are implied. Everything is editable.
func Starter(template string) *Content {
	switch template {
	case "blog":
		return starterBlog()
	case "portfolio":
		return starterPortfolio()
	case "app_showcase":
		return starterApp()
	}
	return starterCorporate()
}
