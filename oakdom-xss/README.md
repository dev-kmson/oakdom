# oakdom-xss

XSS sanitization filter for legacy Spring MVC and pure servlet environments using the `javax.servlet` API.

Wraps every incoming HTTP request with a sanitizing wrapper that transparently cleans parameter values before they reach your application code — no changes to your controllers required.

## Requirements

- JDK 1.8+
- `javax.servlet` API (Tomcat 9 or below, Jetty 10 or below)

> **Note:** This module targets `javax.servlet` only. Environments using `jakarta.servlet`
> (Tomcat 10+, Spring Boot 3.x) are not supported by this module.
> Jakarta support is provided separately via `oakdom-xss-jakarta` _(coming soon)_.

## Installation

**Maven**
```xml
<dependency>
    <groupId>io.oakdom</groupId>
    <artifactId>oakdom-xss</artifactId>
    <version>{version}</version>
</dependency>
```

**Gradle**
```groovy
implementation 'io.oakdom:oakdom-xss:{version}'
```

## Quick Start

Register `OakdomXssFilter` in `web.xml`. That's it — all request parameters are sanitized with the default blacklist mode out of the box.

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

oakdom-xss supports two filter modes.

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

Alternatively, pass an `XssConfig` instance directly to the constructor (useful in non-web.xml setups):

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

## Rule Priority

When multiple rules could apply, the most specific rule wins:

| Priority | Rule type |
|----------|-----------|
| 1 (highest) | URL pattern + parameter name |
| 2 | Parameter name only |
| 3 | URL pattern only |
| 4 (lowest) | Global filter mode |

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

The following CSS properties are excluded by default for security reasons and are not added even if requested implicitly:

| Property | Reason |
|----------|--------|
| `position`, `z-index`, `inset-*` | Phishing overlay risk — elements can be positioned over other content |
| `mix-blend-mode` | Overlay-based UI obscuring attacks |
| `pointer-events` | Clickjacking via disabling UI elements |

These can be explicitly added via `addAllowedCssProperty()` if your application requires them and you accept the risk.

---

## License

Apache License 2.0. See [LICENSE](../LICENSE) for details.
