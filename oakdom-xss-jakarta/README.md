# oakdom-xss-jakarta

XSS sanitization filter for legacy Spring MVC and servlet environments using the `jakarta.servlet` API.

Wraps every incoming HTTP request with a sanitizing wrapper that transparently cleans request data before it reaches your application code — no changes to your controllers required.

- **Request parameters** (`application/x-www-form-urlencoded`, `multipart/form-data`, query string) — sanitized on access via `getParameter()`.
- **JSON request bodies** (`application/json`) — all string values within the JSON structure are sanitized before the body is read by application code.

## Requirements

- JDK 17+
- `jakarta.servlet` API (Tomcat 10.1+)
- Compatible with any version of Spring MVC that supports `jakarta.servlet`

> **Note:** This module targets `jakarta.servlet` only. Environments using `javax.servlet`
> (Tomcat 9 or below) are not supported by this module.
> javax.servlet support is provided separately via `oakdom-xss`.

## Installation

**Maven**
```xml
<dependency>
    <groupId>io.oakdom</groupId>
    <artifactId>oakdom-xss-jakarta</artifactId>
    <version>{version}</version>
</dependency>
```

**Gradle**
```groovy
implementation 'io.oakdom:oakdom-xss-jakarta:{version}'
```

## Quick Start

Register `OakdomXssFilter` in `web.xml`. That's it — all request parameters are sanitized with the default BLACKLIST mode out of the box.

```xml
<filter>
    <filter-name>xssFilter</filter-name>
    <filter-class>io.oakdom.xss.filter.OakdomXssFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>xssFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

> The default behavior escapes `&`, `<`, `>`, `"`, `'` in every parameter value of every request.

---

## Filter Modes

oakdom-xss-jakarta supports two filter modes.

### BLACKLIST (default)

Escapes a defined set of HTML-significant characters. Safe for most general-purpose form inputs where HTML is not expected.

| Character | Escaped to |
|-----------|-----------|
| `&` | `&amp;` |
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&#x27;` |

### WHITELIST

Intended for rich text editor inputs where users are expected to submit HTML. Allows a carefully curated set of safe tags and attributes while escaping everything else. Safe tags include headings, paragraphs, lists, tables, links, images, video, and more. The `style` attribute is allowed but CSS-sanitized — only safe properties pass through and dangerous patterns (`expression()`, `javascript:`, `vbscript:`, `-moz-binding`, `@import`) are always rejected.

Use WHITELIST mode selectively — only for parameters that genuinely accept HTML content.

---

## Configuration

### Default behavior (no configuration needed)

Register `OakdomXssFilter` directly. All parameters on all URLs are filtered with BLACKLIST mode.

### Custom configuration

Extend `OakdomXssFilter` and override the `configure()` method to return a custom `XssConfig`. Then register your subclass in `web.xml`.

```java
public class MyXssFilter extends OakdomXssFilter {

    @Override
    protected XssConfig configure() {
        return XssConfig.builder()
                .globalFilterMode(FilterMode.BLACKLIST)
                .filterRule("/api/editor/**", "content", FilterMode.WHITELIST)
                .excludeUrl("/api/raw/**")
                .build();
    }
}
```

```xml
<filter>
    <filter-name>xssFilter</filter-name>
    <filter-class>com.example.MyXssFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>xssFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

Alternatively, pass an `XssConfig` instance directly to the constructor:

```java
OakdomXssFilter filter = new OakdomXssFilter(
    XssConfig.builder()
        .globalFilterMode(FilterMode.BLACKLIST)
        .build()
);
```

---

## Filter Rules

Filter rules override the global filter mode for specific URLs or parameters.

```java
XssConfig.builder()
    // Override mode for a specific URL pattern (applies to all parameters on that URL)
    .filterRuleForUrl("/api/editor/**", FilterMode.WHITELIST)

    // Override mode for a specific parameter name (applies to that parameter on any URL)
    .filterRuleForParam("htmlContent", FilterMode.WHITELIST)

    // Override mode for a specific URL + parameter combination
    .filterRule("/api/editor/**", "rawBody", FilterMode.BLACKLIST)

    .build();
```

URL patterns follow Ant-style matching: `?` matches one character, `*` matches zero or more characters within a path segment, `**` matches zero or more path segments.

---

## Exclude Rules

Exclude rules skip XSS filtering entirely for specific URLs or parameters — the raw value is passed through unchanged.

```java
XssConfig.builder()
    // Skip filtering for all parameters on the given URL pattern
    .excludeUrl("/api/upload/**")

    // Skip filtering for the given parameter on any URL
    .excludeParam("csrfToken")

    // Skip filtering for the given parameter only on the given URL
    .excludeRule("/api/editor/**", "signature")

    .build();
```

---

## JSON Request Body

For `application/json` requests, all string values within the JSON body are sanitized before application code reads the body. Non-string values (numbers, booleans, nulls) are preserved as-is. Nested objects and arrays are traversed recursively.

```
Input:  {"title": "<script>alert(1)</script>", "count": 42}
Output: {"title": "&lt;script&gt;alert(1)&lt;/script&gt;", "count": 42}
```

**Rule applicability for JSON body:**

| Rule type | Applies to JSON body |
|-----------|---------------------|
| Global filter mode | ✅ |
| URL pattern rule (`filterRuleForUrl`) | ✅ |
| Parameter rule (`filterRuleForParam`) | ❌ — param rules apply to query string / form data only |
| URL + parameter rule (`filterRule`) | ❌ — param rules apply to query string / form data only |

To skip JSON body sanitization for specific URLs, use `excludeUrl`:

```java
XssConfig.builder()
    .excludeUrl("/api/raw/**")
    .build();
```

---

## Annotation-Based Control

Per-handler-method XSS control is available via annotations. Annotations take priority over configuration-based rules.

### Setup

Register `OakdomXssAnnotationInterceptor` in your Spring MVC configuration:

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new OakdomXssAnnotationInterceptor());
    }
}
```

### Annotations

#### `@OakdomXssExclude`

Skips XSS filtering entirely. Applicable at method or parameter level.

```java
// Skip XSS filtering for all parameters and the request body on this handler method
@OakdomXssExclude
@PostMapping("/api/raw")
public void handleRaw(@RequestParam String data) { ... }

// Skip XSS filtering only for the 'rawContent' parameter
@PostMapping("/api/upload")
public void handleUpload(
        @RequestParam String title,
        @OakdomXssExclude @RequestParam String rawContent) { ... }

// Skip XSS filtering for the entire request body
@PostMapping("/api/body-raw")
public void handleBodyRaw(@OakdomXssExclude @RequestBody MyDto dto) { ... }
```

#### `@OakdomXssFilterMode`

Overrides the filter mode for the handler method, a specific parameter, or the request body.

```java
// Apply WHITELIST mode to all parameters and the request body on this handler method
@OakdomXssFilterMode(FilterMode.WHITELIST)
@PostMapping("/api/editor")
public void handleEditor(@RequestParam String content) { ... }

// Apply WHITELIST mode only to the 'content' parameter
@PostMapping("/api/post")
public void handlePost(
        @RequestParam String title,
        @OakdomXssFilterMode(FilterMode.WHITELIST) @RequestParam String content) { ... }

// Apply WHITELIST mode to the entire request body
@PostMapping("/api/body-editor")
public void handleBodyEditor(
        @OakdomXssFilterMode(FilterMode.WHITELIST) @RequestBody MyDto dto) { ... }
```

### JSON Body Behavior

- Annotations on `@RequestBody` apply to the **entire JSON body** — field-level control within the JSON structure is not supported.
- Annotations on `@RequestParam` parameters have **no effect on the JSON body**. Use `@RequestBody`-level or method-level annotations to control JSON body filtering.
- Method-level annotations apply to **both parameters and the JSON body**.

### Priority

When multiple sources could apply, the most specific wins:

| Priority | Source |
|----------|--------|
| 1 (highest) | Parameter-level annotation (`@RequestParam` or `@RequestBody`) |
| 2 | Method-level annotation |
| 3 | Config rule — URL pattern + parameter name |
| 4 | Config rule — parameter name only |
| 5 | Config rule — URL pattern only |
| 6 (lowest) | Global filter mode |

---

## Blacklist Customization

The default blacklist escapes five characters. You can add or remove characters.

```java
XssConfig.builder()
    // Add / and ` to the escape set (pre-defined entities used for these two)
    .addEscapeChar('/', '`')

    // Remove ' from the escape set (discouraged — degrades XSS protection)
    .removeEscapeChar('\'')

    .build();
```

> Removing any of the five default characters is permitted but strongly discouraged.

---

## Whitelist Customization

The whitelist has built-in defaults for allowed HTML tags and CSS properties. You can extend or narrow them.

### Allowed tags

Add or remove HTML tags from the whitelist:

```java
XssConfig.builder()
    // Allow <iframe> and <embed> in addition to defaults
    .addAllowedTag("iframe", "embed")

    // Remove <strike> from the default allowed set
    .removeAllowedTag("strike")

    .build();
```

### Allowed CSS properties

Add or remove CSS properties from the whitelist:

```java
XssConfig.builder()
    // Allow additional CSS properties
    .addAllowedCssProperty("position", "z-index")

    // Remove a CSS property from the default allowed set
    .removeAllowedCssProperty("float")

    .build();
```

### Default allowed HTML tags

| Category | Tags |
|----------|------|
| Inline | `b`, `i`, `em`, `strong`, `u`, `s`, `strike`, `small`, `sub`, `sup`, `cite`, `q`, `code`, `span`, `mark`, `abbr`, `del`, `ins`, `time`, `kbd`, `var`, `samp`, `wbr`, `ruby`, `rt`, `rp`, `bdi`, `bdo`, `dfn` |
| Block | `p`, `div`, `h1`–`h6`, `blockquote`, `pre`, `ul`, `ol`, `li`, `dl`, `dt`, `dd`, `article`, `section`, `aside`, `header`, `footer`, `main`, `nav`, `address`, `details`, `summary`, `hgroup`, `meter`, `progress` |
| Media | `a`, `img`, `picture`, `figure`, `figcaption`, `video`, `audio`, `source`, `track` |
| Table | `table`, `thead`, `tbody`, `tfoot`, `tr`, `th`, `td`, `caption`, `col`, `colgroup` |
| Other | `br`, `hr` |

### Default allowed CSS property categories

| Category | Examples |
|----------|---------|
| Color & background | `color`, `background`, `background-color`, `background-image`, `background-clip`, … |
| Typography | `font-*`, `text-*`, `line-height`, `letter-spacing`, `word-spacing`, `white-space`, `direction`, `writing-mode`, `ruby-*`, … |
| Box model | `margin`, `padding` and all physical/logical longhands |
| Border | `border` and all physical/logical longhands, `border-image-*`, `border-radius` variants |
| Sizing & display | `width`, `height`, `min-*`, `max-*`, logical sizes, `display`, `visibility`, `opacity`, `float`, `overflow`, `box-sizing`, `box-shadow`, `clip-path`, `aspect-ratio`, … |
| Flexbox | `flex`, `flex-*`, `justify-*`, `align-*`, `place-*`, `gap`, `order` |
| Grid | `grid`, `grid-template-*`, `grid-column-*`, `grid-row-*`, `grid-auto-*`, `grid-area` |
| Multi-column | `columns`, `column-count`, `column-width`, `column-rule-*`, `column-span` |
| Transform & animation | `transform`, `rotate`, `scale`, `translate`, `animation`, `transition`, `will-change`, `filter`, `backdrop-filter`, … |
| Scroll-driven animation | `animation-timeline`, `animation-range-*`, `scroll-timeline-*`, `view-timeline-*` |
| Scroll | `scroll-behavior`, `scroll-snap-*`, `scroll-padding-*`, `scroll-margin-*`, `overscroll-behavior-*`, `scrollbar-*` |
| UI & interaction | `cursor`, `resize`, `accent-color`, `caret-color`, `appearance`, `user-select`, `touch-action` |
| Container queries | `container`, `container-type`, `container-name`, `content-visibility`, `contain`, `contain-intrinsic-*` |
| Mask | `mask` and all longhands, `mask-border-*`, `-webkit-mask-*` |
| SVG presentation | `fill`, `stroke` and all longhands, `clip-rule`, `paint-order`, `dominant-baseline`, `stop-color`, `marker-*`, `d`, `cx`, `cy`, `r`, `rx`, `ry`, `x`, `y`, … |
| Other | `list-style-*`, `table-layout`, `counter-*`, `shape-outside`, `quotes`, `orphans`, `widows`, `break-*`, `color-scheme`, `isolation`, `zoom`, … |

### Intentionally excluded CSS properties

The following CSS properties are not included in the default whitelist for security reasons:

| Property | Reason |
|----------|--------|
| `position`, `z-index`, `inset-*` | Phishing overlay risk — elements can be positioned over other content |
| `mix-blend-mode` | Overlay-based UI obscuring attacks |
| `pointer-events` | Clickjacking via disabling UI elements |

These can be explicitly added via `addAllowedCssProperty()` if your application requires them and you accept the risk.

---

## License

Apache License 2.0. See [LICENSE](../LICENSE) for details.
