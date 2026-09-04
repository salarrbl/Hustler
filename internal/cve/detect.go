package cve

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Detection for client-side JS libraries and server-side technologies.
//
// Client side combines four evidence sources (strongest first):
//  1. banner/global version markers inside file content
//  2. version pinned in the script URL (CDN @x.y.z, -x.y.z.min.js, ?ver=)
//  3. package.json / dependency blocks (sourcemaps, bundled manifests)
//  4. (callers) lockfiles fetched alongside
//
// Server side combines wappalyzer output (handled in module.go) with
// deterministic header and body rules below, so version disclosure in
// Server/X-Powered-By/meta-generator is caught even when wappalyzer
// has no fingerprint for the product.

// DetectedLib is one library version observation.
type DetectedLib struct {
	Library  string
	Version  string
	Evidence string // short snippet proving the match
	Origin   string // "banner", "global", "url", "package.json"
}

// DetectedTech is one server technology observation.
type DetectedTech struct {
	Tech     string
	Version  string // may be "" when only the product is known
	Evidence string // e.g. "Server: Apache/2.4.49"
	Origin   string // "header:<name>", "meta", "body", "wappalyzer"
}

// ---------------------------------------------------------------------------
// Client-side signatures
// ---------------------------------------------------------------------------

type clientSig struct {
	lib      string
	patterns []string
}

// clientSigs maps library -> banner/global version regexes. Every pattern
// must capture the version in group 1.
var clientSigs = []clientSig{
	{"jquery", []string{
		`jQuery(?: JavaScript Library)? v?(\d+\.\d+\.\d+[^"'\s;]*)`,
		`jquery[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"jquery-ui", []string{
		`jQuery UI[^\d]*(\d+\.\d+\.\d+[^"'\s;]*)`,
		`jquery-ui[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"jquery-validation", []string{`jQuery Validation Plugin (\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"datatables", []string{`DataTables (\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"select2", []string{`Select2 (\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"lodash", []string{
		`lodash[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
		`_.VERSION\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
	}},
	{"underscore", []string{
		`Underscore\.js,? v?(\d+\.\d+\.\d+[^"'\s;]*)`,
		`_\.VERSION\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
	}},
	{"react", []string{
		`React\.version\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
		`react[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"react-dom", []string{`react-dom[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"next", []string{`next[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"vue", []string{
		`Vue\.version\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
		`vue[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"angular", []string{
		`angular\.version\s*=\s*\{[^}]*?["']?full["']?\s*:\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
		`angular[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"svelte", []string{`svelte[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"ember", []string{
		`Ember\.VERSION\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
		`ember[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"backbone", []string{
		`Backbone\.VERSION\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
		`backbone[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"knockout", []string{`knockout[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"moment", []string{
		`moment\.version\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
		`moment[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"dayjs", []string{`dayjs[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"bootstrap", []string{
		`Bootstrap v?(\d+\.\d+\.\d+[^"'\s;]*)`,
		`bootstrap[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"axios", []string{
		`axios v?(\d+\.\d+\.\d+[^"'\s;]*)`,
		`axios[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"core-js", []string{`core-js[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"d3", []string{
		`d3\.version\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
		`d3[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"chart.js", []string{
		`Chart\.version\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
		`chart\.?js[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"highcharts", []string{`Highcharts\.version\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`}},
	{"echarts", []string{`echarts[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"three", []string{
		`THREE\.REVISION\s*=\s*["'](\d+[^"']*)["']`,
		`three[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"gsap", []string{`gsap[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"swiper", []string{
		`Swiper,? v?(\d+\.\d+\.\d+[^"'\s;]*)`,
		`swiper[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"handlebars", []string{
		`Handlebars\.VERSION\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
		`handlebars[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"mustache", []string{`mustache[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"marked", []string{`marked v?(\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"markdown-it", []string{`markdown-it[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"dompurify", []string{
		`DOMPurify[^\d]*(\d+\.\d+\.\d+[^"'\s;]*)`,
		`dompurify[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"tinymce", []string{
		`tinymce\.majorVersion\s*=\s*["'](\d+)["']`,
		`tinymce[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"ckeditor", []string{`CKEDITOR\.version\s*=\s*["'](\d+\.\d+\.\d*[^"']*)["']`}},
	{"quill", []string{`quill[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"froala", []string{`froala[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"pdf.js", []string{`pdf\.js[^\d]*v?(\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"mathjax", []string{`MathJax\.js[^\d]*v?(\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"socket.io", []string{
		`socket\.io[^\d]*v?(\d+\.\d+\.\d+[^"'\s;]*)`,
		`io\.version\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`,
	}},
	{"webpack", []string{`webpack[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"typescript", []string{`TypeScript\s+(\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"mootools", []string{`MooTools[^\d]*(\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"prototype", []string{`Prototype JavaScript framework,? v?(\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"dojo", []string{
		`dojo\.version\s*=\s*\{[^}]*?major\s*:\s*(\d+)`,
		`dojo[.-](\d+\.\d+\.\d+[^"'\s;]*)`,
	}},
	{"extjs", []string{`Ext\.version\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`}},
	{"yui", []string{`YUI[^\d]*(\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"video.js", []string{`videojs\.VERSION\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`}},
	{"plupload", []string{`plupload[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"jszip", []string{`JSZip v?(\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"moment-timezone", []string{`moment-timezone[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"validator", []string{`validator\.version\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`}},
	{"zxcvbn", []string{`zxcvbn[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"highlight.js", []string{`Highlight\.js[^\d]*(\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"prism", []string{`Prism\.manual` /* placeholder: version via URL only */}},
	{"popper", []string{`popper[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"alpinejs", []string{`alpinejs[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
	{"htmx", []string{`htmx\.version\s*=\s*["'](\d+\.\d+\.\d+[^"']*)["']`}},
	{"tailwindcss", []string{`tailwindcss[.-](\d+\.\d+\.\d+[^"'\s;]*)`}},
}

var (
	sigOnce sync.Once
	sigREs  []clientSigRE
)

type clientSigRE struct {
	lib string
	res []*regexp.Regexp
}

// compileSigs compiles signature regexes once, skipping invalid ones.
func compileSigs() {
	sigOnce.Do(func() {
		for _, s := range clientSigs {
			var res []*regexp.Regexp
			for _, p := range s.patterns {
				re, err := regexp.Compile(`(?i)` + p)
				if err != nil {
					continue
				}
				res = append(res, re)
			}
			if len(res) > 0 {
				sigREs = append(sigREs, clientSigRE{lib: s.lib, res: res})
			}
		}
	})
}

// snippet returns a trimmed window around idx for evidence.
func snippet(content string, idx, width int) string {
	start := idx - width
	if start < 0 {
		start = 0
	}
	end := idx + width
	if end > len(content) {
		end = len(content)
	}
	s := strings.ReplaceAll(content[start:end], "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// DetectClientLibraries fingerprints JS libraries from file content and URL.
func DetectClientLibraries(content, jsURL string) []DetectedLib {
	compileSigs()
	seen := make(map[string]bool)
	var out []DetectedLib

	add := func(lib, ver, ev, origin string) {
		ver = strings.Trim(ver, "\"' \t;,")
		// Trim trailing file-type suffixes accidentally captured.
		for _, suf := range []string{".min.js", ".js", ".min"} {
			ver = strings.TrimSuffix(ver, suf)
		}
		if ver == "" {
			return
		}
		key := strings.ToLower(lib) + "|" + ver
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, DetectedLib{Library: lib, Version: ver, Evidence: ev, Origin: origin})
	}

	// 1. Banner / global markers.
	if content != "" {
		for _, s := range sigREs {
			for _, re := range s.res {
				loc := re.FindStringSubmatchIndex(content)
				if loc == nil || len(loc) < 4 || loc[2] < 0 {
					continue
				}
				ver := content[loc[2]:loc[3]]
				origin := "banner"
				if strings.Contains(strings.ToLower(re.String()), "version") {
					origin = "global"
				}
				add(s.lib, ver, snippet(content, loc[0], 80), origin)
				break // one version per pattern family is enough
			}
		}

		// 3. package.json / dependency blocks (sourcemaps, manifests).
		for _, d := range ExtractPackageJSONVersions(content) {
			add(d.Library, d.Version, d.Evidence, "package.json")
		}
	}

	// 2. Version pinned in the script URL.
	if jsURL != "" {
		if lib, ver := ExtractURLVersion(jsURL); lib != "" && ver != "" {
			add(lib, ver, jsURL, "url")
		}
	}

	return out
}

var (
	urlAtVerRe  = regexp.MustCompile(`(?i)@(\d+\.\d+\.\d+[^/?#]*)`)
	urlDashRe   = regexp.MustCompile(`(?i)[-/](\d+\.\d+\.\d+[^/?#]*?)(?:\.min)?\.js(?:[?#]|$)`)
	urlPathRe   = regexp.MustCompile(`(?i)/(\d+\.\d+\.\d+[^/?#]*)/`)
	urlQueryRe  = regexp.MustCompile(`(?i)[?&](?:ver|version|v)=(\d+\.\d+\.\d+[^&#]*)`)
	urlLibRe    = regexp.MustCompile(`(?i)(jquery|lodash|underscore|react|vue|angular|bootstrap|moment|axios|d3|ember|backbone|svelte|next|nuxt|three|gsap|swiper|handlebars|chart|highcharts|tinymce|ckeditor|dojo|mootools|prototype|yui|select2|datatables|knockout|quill|htmx|alpine|popper|core-js|dayjs|marked|dompurify|jszip|video|plupload|socket\.io|webpack|mustache|prism|tailwind)`)
)

// ExtractURLVersion pulls (library, version) from a script URL such as
// https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js or
// /assets/js/bootstrap-5.1.3.min.js?ver=5.1.3
func ExtractURLVersion(jsURL string) (string, string) {
	lower := strings.ToLower(jsURL)
	lib := ""
	if m := urlLibRe.FindStringSubmatch(lower); m != nil {
		lib = NormalizeLibName(m[1])
	}
	ver := ""
	if m := urlAtVerRe.FindStringSubmatch(jsURL); m != nil {
		ver = m[1]
	} else if m := urlDashRe.FindStringSubmatch(jsURL); m != nil {
		ver = m[1]
	} else if m := urlPathRe.FindStringSubmatch(jsURL); m != nil {
		ver = m[1]
	} else if m := urlQueryRe.FindStringSubmatch(jsURL); m != nil {
		ver = m[1]
	}
	if lib == "" || ver == "" {
		return "", ""
	}
	return lib, ver
}

var (
	pkgPairRe = regexp.MustCompile(`"name"\s*:\s*"([^"]+)"\s*,\s*"version"\s*:\s*"([^"]+)"`)
	pkgDepRe  = regexp.MustCompile(`"((?:@[^"/]+/)?[^"/\s]+)"\s*:\s*"[~^>=<v\s]*(\d+\.\d+\.\d+[^"]*)"`)
)

// ExtractPackageJSONVersions finds "name"/"version" pairs and dependency
// maps embedded in sourcemaps or bundled manifests.
func ExtractPackageJSONVersions(content string) []DetectedLib {
	var out []DetectedLib
	seen := make(map[string]bool)
	for _, m := range pkgPairRe.FindAllStringSubmatch(content, 20) {
		name, ver := NormalizeLibName(m[1]), m[2]
		key := name + "|" + ver
		if seen[key] || !looksLikeLib(name) {
			continue
		}
		seen[key] = true
		out = append(out, DetectedLib{Library: name, Version: ver, Evidence: m[0], Origin: "package.json"})
	}
	// Dependency blocks: only trust them inside an obvious manifest context
	// to avoid matching random JSON.
	if strings.Contains(content, `"dependencies"`) || strings.Contains(content, `"packages"`) {
		for _, m := range pkgDepRe.FindAllStringSubmatch(content, 60) {
			name, ver := NormalizeLibName(m[1]), m[2]
			key := name + "|" + ver
			if seen[key] || !looksLikeLib(name) {
				continue
			}
			seen[key] = true
			out = append(out, DetectedLib{Library: name, Version: ver, Evidence: m[0], Origin: "package.json"})
		}
	}
	return out
}

// looksLikeLib filters obvious non-library names from manifest parsing.
func looksLikeLib(name string) bool {
	n := strings.ToLower(name)
	if n == "" || len(n) > 60 {
		return false
	}
	skip := []string{"test", "example", "sample", "demo", "hustler", "webpack", "babel-runtime"}
	for _, s := range skip {
		if strings.Contains(n, s) && n != "webpack" {
			return false
		}
	}
	return true
}

// NormalizeLibName canonicalises library slugs across evidence sources.
func NormalizeLibName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	n = strings.TrimPrefix(n, "@")
	aliases := map[string]string{
		"vue.js": "vue", "react-dom": "react-dom", "chart": "chart.js",
		"chartjs": "chart.js", "socket.io-client": "socket.io", "socket.io": "socket.io",
		"three.js": "three", "video.js": "video.js", "videojs": "video.js",
		"highlight.js": "highlight.js", "node.js": "nodejs", "alpine.js": "alpinejs",
		"datatables.net": "datatables", "jquery-ui-dist": "jquery-ui",
		"moment-timezone": "moment-timezone", "popper.js": "popper",
		"@popperjs/core": "popper", "corejs": "core-js",
	}
	if a, ok := aliases[n]; ok {
		return a
	}
	if i := strings.Index(n, "/"); i >= 0 {
		n = n[i+1:] // strip npm scope
	}
	return n
}

// ---------------------------------------------------------------------------
// Server-side detection: header + body rules
// ---------------------------------------------------------------------------

type headerRule struct {
	header string
	re     *regexp.Regexp
	tech   string
}

var headerRules = []headerRule{
	{"Server", regexp.MustCompile(`(?i)Apache/(\d[\d.]*)`), "apache"},
	{"Server", regexp.MustCompile(`(?i)nginx/(\d[\d.]*)`), "nginx"},
	{"Server", regexp.MustCompile(`(?i)Microsoft-IIS/(\d[\d.]*)`), "iis"},
	{"Server", regexp.MustCompile(`(?i)LiteSpeed`), "litespeed"},
	{"Server", regexp.MustCompile(`(?i)OpenResty/([\d.]+)`), "openresty"},
	{"Server", regexp.MustCompile(`(?i)Apache-Coyote/[\d.]*`), "tomcat"},
	{"Server", regexp.MustCompile(`(?i)Jetty[\(/ ]([\d.()]+)`), "jetty"},
	{"Server", regexp.MustCompile(`(?i)Gunicorn/([\d.]+)`), "gunicorn"},
	{"Server", regexp.MustCompile(`(?i)Werkzeug/([\d.]+)`), "werkzeug"},
	{"Server", regexp.MustCompile(`(?i)Cowboy`), "cowboy"},
	{"Server", regexp.MustCompile(`(?i)Thin\s+([\d.]+)`), "thin"},
	{"Server", regexp.MustCompile(`(?i)Unicorn`), "unicorn"},
	{"Server", regexp.MustCompile(`(?i)WEBrick/([\d.]+)`), "webrick"},
	{"Server", regexp.MustCompile(`(?i)SimpleHTTP/([\d.]+)`), "python-simplehttp"},
	{"Server", regexp.MustCompile(`(?i)openresty`), "openresty"},
	{"X-Powered-By", regexp.MustCompile(`(?i)PHP/([\d.]+)`), "php"},
	{"X-Powered-By", regexp.MustCompile(`(?i)Express`), "express"},
	{"X-Powered-By", regexp.MustCompile(`(?i)Next\.js`), "next"},
	{"X-Powered-By", regexp.MustCompile(`(?i)ASP\.NET`), "aspnet"},
	{"X-Powered-By", regexp.MustCompile(`(?i)Servlet/([\d.]+)`), "servlet"},
	{"X-Powered-By", regexp.MustCompile(`(?i)PleskLin`), "plesk"},
	{"X-Powered-By", regexp.MustCompile(`(?i)Django/([\d.]+)`), "django"},
	{"X-Powered-By", regexp.MustCompile(`(?i)Nuxt`), "nuxt"},
	{"X-AspNet-Version", regexp.MustCompile(`([\d.]+)`), "aspnet"},
	{"X-AspNetMvc-Version", regexp.MustCompile(`([\d.]+)`), "aspnetmvc"},
	{"X-Generator", regexp.MustCompile(`(?i)Drupal\s+([\d.]+)`), "drupal"},
	{"X-Generator", regexp.MustCompile(`(?i)WordPress\s+([\d.]+)`), "wordpress"},
	{"X-Generator", regexp.MustCompile(`(?i)Joomla!?\s+([\d.]+)`), "joomla"},
	{"X-Generator", regexp.MustCompile(`(?i)Ghost\s+([\d.]+)`), "ghost"},
	{"X-Drupal-Cache", regexp.MustCompile(`.+`), "drupal"},
	{"X-Joomla-Cache", regexp.MustCompile(`.+`), "joomla"},
	{"X-Powered-By", regexp.MustCompile(`(?i)WAF/([\d.]+)`), "waf"},
}

type bodyRule struct {
	re     *regexp.Regexp
	tech   string
	origin string
}

var bodyRules = []bodyRule{
	{regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([\d.]+)`), "wordpress", "meta"},
	{regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']Drupal\s+([\d.]+)`), "drupal", "meta"},
	{regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']Joomla!?\s+([\d.]+)`), "joomla", "meta"},
	{regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']Ghost\s+([\d.]+)`), "ghost", "meta"},
	{regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']Hugo\s+([\d.]+)`), "hugo", "meta"},
	{regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']Next\.js`), "next", "meta"},
	{regexp.MustCompile(`wp-content|wp-includes|wp-json`), "wordpress", "body"},
	{regexp.MustCompile(`(?i)drupal\.settings|sites/(?:all|default)/modules`), "drupal", "body"},
	{regexp.MustCompile(`(?i)/media/jui/|option=com_`), "joomla", "body"},
	{regexp.MustCompile(`(?i)Apache/(\d[\d.]*) Server at`), "apache", "body"},
	{regexp.MustCompile(`(?i)nginx/(\d[\d.]*)`), "nginx", "body"},
	{regexp.MustCompile(`(?i)OpenSSL/(\d[\d.]*[a-z]*)`), "openssl", "body"},
	{regexp.MustCompile(`(?i)PHP/(\d[\d.]*)`), "php", "body"},
	{regexp.MustCompile(`(?i)_next/static`), "next", "body"},
	{regexp.MustCompile(`(?i)__NUXT__`), "nuxt", "body"},
	{regexp.MustCompile(`(?i)ng-version="([\d.]+)"`), "angular", "body"},
	{regexp.MustCompile(`(?i)<!--\s*Powered by (?:WooCommerce|PrestaShop)\s*([\d.]*)`), "ecommerce", "body"},
}

// DetectServerTechnologies fingerprints server tech from response headers
// and body without any external service.
func DetectServerTechnologies(resp HTTPResponse) []DetectedTech {
	var out []DetectedTech
	seen := make(map[string]bool)

	add := func(tech, ver, ev, origin string) {
		tech = NormalizeTechName(tech)
		key := tech + "|" + ver + "|" + origin
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, DetectedTech{Tech: tech, Version: ver, Evidence: ev, Origin: origin})
	}

	if resp.Headers != nil {
		for _, r := range headerRules {
			vals := resp.Headers.Values(r.header)
			if len(vals) == 0 && http.CanonicalHeaderKey(r.header) != r.header {
				vals = resp.Headers.Values(http.CanonicalHeaderKey(r.header))
			}
			for _, v := range vals {
				m := r.re.FindStringSubmatch(v)
				if m == nil {
					continue
				}
				ver := ""
				if len(m) > 1 {
					ver = strings.Trim(m[1], "() ")
				}
				add(r.tech, ver, r.header+": "+v, "header:"+strings.ToLower(r.header))
			}
		}
	}

	if resp.Body != "" {
		body := resp.Body
		if len(body) > 512*1024 {
			body = body[:512*1024]
		}
		for _, r := range bodyRules {
			m := r.re.FindStringSubmatch(body)
			if m == nil {
				continue
			}
			ver := ""
			if len(m) > 1 {
				ver = m[1]
			}
			add(r.tech, ver, snippet(body, strings.Index(body, m[0]), 60), r.origin)
		}
	}

	return out
}

// NormalizeTechName canonicalises server technology names.
func NormalizeTechName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	aliases := map[string]string{
		"apache http server": "apache", "apache-http-server": "apache",
		"apache coyote": "tomcat", "microsoft-iis": "iis",
		"internet information services": "iis", "node.js": "nodejs",
		"vue.js": "vue", "open resty": "openresty",
		"php-fpm": "php", "phusion passenger": "passenger",
		"litespeed web server": "litespeed",
	}
	if a, ok := aliases[n]; ok {
		return a
	}
	return n
}

// OSVTargetForTech maps a technology to an OSV (ecosystem, package) pair
// for live lookups. Only ecosystems where upstream versions compare
// correctly are mapped; distro-versioned server software (nginx, apache,
// openssl ...) is intentionally excluded and handled via the NVD CPE
// cache instead.
func OSVTargetForTech(tech string) (string, string, bool) {
	tech = NormalizeTechName(tech)
	npmLibs := map[string]string{
		"jquery": "jquery", "jquery-ui": "jquery-ui", "lodash": "lodash",
		"underscore": "underscore", "react": "react", "react-dom": "react-dom",
		"next": "next", "vue": "vue", "angular": "angular", "svelte": "svelte",
		"ember": "ember-source", "backbone": "backbone", "knockout": "knockout",
		"moment": "moment", "dayjs": "dayjs", "bootstrap": "bootstrap",
		"axios": "axios", "core-js": "core-js", "d3": "d3", "chart.js": "chart.js",
		"highcharts": "highcharts", "echarts": "echarts", "three": "three",
		"gsap": "gsap", "swiper": "swiper", "handlebars": "handlebars",
		"mustache": "mustache", "marked": "marked", "markdown-it": "markdown-it",
		"dompurify": "dompurify", "tinymce": "tinymce", "ckeditor": "ckeditor4",
		"quill": "quill", "pdf.js": "pdfjs-dist", "mathjax": "mathjax",
		"socket.io": "socket.io", "webpack": "webpack", "mootools": "mootools",
		"select2": "select2", "datatables": "datatables.net",
		"jszip": "jszip", "validator": "validator", "htmx": "htmx.org",
		"alpinejs": "alpinejs", "popper": "@popperjs/core",
		"express": "express", "typescript": "typescript", "vite": "vite",
		"tailwindcss": "tailwindcss", "prism": "prismjs",
		"highlight.js": "highlight.js", "video.js": "video.js",
		"plupload": "plupload", "dojo": "dojo", "prototype": "prototype",
		"moment-timezone": "moment-timezone",
		"jquery-validation": "jquery-validation",
	}
	if pkg, ok := npmLibs[tech]; ok && pkg != "" {
		return "npm", pkg, true
	}
	pypi := map[string]string{
		"django": "Django", "flask": "Flask", "werkzeug": "Werkzeug",
		"gunicorn": "gunicorn", "pillow": "Pillow", "requests": "requests",
		"urllib3": "urllib3", "jinja2": "Jinja2",
	}
	if pkg, ok := pypi[tech]; ok {
		return "PyPI", pkg, true
	}
	packagist := map[string]string{
		"laravel": "laravel/framework", "symfony": "symfony/symfony",
		"drupal": "drupal/core", "joomla": "joomla/joomla-cms",
	}
	if pkg, ok := packagist[tech]; ok {
		return "Packagist", pkg, true
	}
	gomod := map[string]string{
		"caddy": "github.com/caddyserver/caddy/v2",
		"traefik": "github.com/traefik/traefik",
	}
	if pkg, ok := gomod[tech]; ok {
		return "Go", pkg, true
	}
	return "", "", false
}

// CPEForTech maps server-side products to NVD CPE 2.3 prefixes used by
// the offline NVD cache (see update.go).
func CPEForTech(tech string) (string, bool) {
	tech = NormalizeTechName(tech)
	cpes := map[string]string{
		"apache":     "cpe:2.3:a:apache:http_server",
		"nginx":      "cpe:2.3:a:f5:nginx",
		"php":        "cpe:2.3:a:php:php",
		"openssl":    "cpe:2.3:a:openssl:openssl",
		"iis":        "cpe:2.3:a:microsoft:internet_information_services",
		"tomcat":     "cpe:2.3:a:apache:tomcat",
		"jetty":      "cpe:2.3:a:eclipse:jetty",
		"wordpress":  "cpe:2.3:a:wordpress:wordpress",
		"drupal":     "cpe:2.3:a:drupal:drupal",
		"joomla":     "cpe:2.3:a:joomla:joomla",
		"nodejs":     "cpe:2.3:a:nodejs:node.js",
		"express":    "cpe:2.3:a:expressjs:express",
		"next":       "cpe:2.3:a:vercel:next.js",
		"django":     "cpe:2.3:a:djangoproject:django",
		"flask":      "cpe:2.3:a:pallets:flask",
		"laravel":    "cpe:2.3:a:laravel:laravel",
		"lighttpd":   "cpe:2.3:a:lighttpd:lighttpd",
		"varnish":    "cpe:2.3:a:varnish-software:varnish_cache",
		"haproxy":    "cpe:2.3:a:haproxy:haproxy",
		"squid":      "cpe:2.3:a:squid-cache:squid",
		"openresty":  "cpe:2.3:a:openresty:openresty",
		"litespeed":  "cpe:2.3:a:litespeedtech:litespeed_web_server",
		"struts":     "cpe:2.3:a:apache:struts",
		"jquery":     "cpe:2.3:a:jquery:jquery",
		"bootstrap":  "cpe:2.3:a:getbootstrap:bootstrap",
		"angular":    "cpe:2.3:a:angular:angular",
		"vue":        "cpe:2.3:a:vue:vue.js",
		"react":      "cpe:2.3:a:facebook:react",
		"spring":     "cpe:2.3:a:vmware:spring_framework",
		"weblogic":   "cpe:2.3:a:oracle:weblogic_server",
		"websphere":  "cpe:2.3:a:ibm:websphere_application_server",
	}
	cpe, ok := cpes[tech]
	return cpe, ok
}

// scriptSrcRe extracts script src URLs from HTML for live scans.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// ExtractScriptURLs resolves <script src> URLs against a base page URL.
func ExtractScriptURLs(basePage, html string) []string {
	base, err := url.Parse(basePage)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, 40) {
		src := strings.TrimSpace(m[1])
		if src == "" || strings.HasPrefix(src, "data:") || strings.HasPrefix(src, "blob:") {
			continue
		}
		ref, err := url.Parse(src)
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref).String()
		if !strings.HasPrefix(abs, "http://") && !strings.HasPrefix(abs, "https://") {
			continue
		}
		if !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	return out
}
