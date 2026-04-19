# oakdom-xss-spring-boot3-starter

XSS auto-configuration for Spring Boot 3.x applications.

Registers `OakdomXssFilter` automatically — no `web.xml`, no manual filter bean required. Add the dependency and all incoming request data is sanitized out of the box.

- **Request parameters** (`application/x-www-form-urlencoded`, `multipart/form-data`, query string) — sanitized on access.
- **JSON request bodies** (`application/json`) — all string values within the JSON structure are sanitized before the body is read by application code.

## Requirements

- JDK 17+
- Spring Boot 3.x

## Installation

**Maven**
```xml
<dependency>
    <groupId>io.oakdom</groupId>
    <artifactId>oakdom-xss-spring-boot3-starter</artifactId>
    <version>{version}</version>
</dependency>
```

**Gradle**
```groovy
implementation 'io.oakdom:oakdom-xss-spring-boot3-starter:{version}'
```

## Quick Start

Add the dependency. That's it — all request parameters are sanitized with the default BLACKLIST mode on every request.

> The default behavior escapes `&`, `<`, `>`, `"`, `'` in every parameter value of every request.

---

## Configuration

All settings are bound under the `oakdom.xss` prefix in `application.properties` or `application.yml`.

### Basic properties

| Property | Default | Description |
|----------|---------|-------------|
| `oakdom.xss.enabled` | `true` | Enable or disable the XSS filter |
| `oakdom.xss.global-filter-mode` | `BLACKLIST` | Global filter mode: `BLACKLIST` or `WHITELIST` |
| `oakdom.xss.exclude-urls` | (none) | Comma-separated URL patterns to skip filtering entirely |
| `oakdom.xss.exclude-params` | (none) | Comma-separated parameter names to skip filtering on any URL |
| `oakdom.xss.filter-order` | `Integer.MIN_VALUE` | Filter chain order (default runs before all other filters) |

### Filter rules

Override the global filter mode for specific URLs or parameters.

| Property | Description |
|----------|-------------|
| `oakdom.xss.filter-rules[n].url-pattern` | Ant-style URL pattern (optional) |
| `oakdom.xss.filter-rules[n].param` | Parameter name (optional) |
| `oakdom.xss.filter-rules[n].mode` | `BLACKLIST` or `WHITELIST` |

If both `url-pattern` and `param` are set, the rule applies to that combination. If only `url-pattern` is set, the rule applies to all parameters on that URL. If only `param` is set, the rule applies to that parameter on any URL.

### Exclude rules

Skip XSS filtering entirely for a specific URL and parameter combination.

| Property | Description |
|----------|-------------|
| `oakdom.xss.exclude-rules[n].url-pattern` | Ant-style URL pattern |
| `oakdom.xss.exclude-rules[n].param` | Parameter name |

### Example

```properties
oakdom.xss.global-filter-mode=BLACKLIST

# Apply WHITELIST mode to the 'content' parameter on /api/editor/**
oakdom.xss.filter-rules[0].url-pattern=/api/editor/**
oakdom.xss.filter-rules[0].param=content
oakdom.xss.filter-rules[0].mode=WHITELIST

# Apply WHITELIST mode to all parameters on /api/public/**
oakdom.xss.filter-rules[1].url-pattern=/api/public/**
oakdom.xss.filter-rules[1].mode=WHITELIST

# Apply WHITELIST mode to 'htmlBody' on any URL
oakdom.xss.filter-rules[2].param=htmlBody
oakdom.xss.filter-rules[2].mode=WHITELIST

# Skip filtering for specific URLs or parameters
oakdom.xss.exclude-urls=/api/upload/**,/api/raw/**
oakdom.xss.exclude-params=csrfToken

# Skip filtering for 'rawData' only on /api/editor/**
oakdom.xss.exclude-rules[0].url-pattern=/api/editor/**
oakdom.xss.exclude-rules[0].param=rawData
```

---

## Filter Modes

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

## Blacklist Customization

The default blacklist escapes five characters. You can add or remove characters via properties.

```properties
# Add / and ` to the escape set
oakdom.xss.add-escape-chars=/,`

# Remove ' from the escape set (discouraged — degrades XSS protection)
oakdom.xss.remove-escape-chars='
```

> Removing any of the five default characters is permitted but strongly discouraged.

---

## Whitelist Customization

The whitelist has built-in defaults for allowed HTML tags and CSS properties. You can extend or narrow them via properties.

### Allowed tags

```properties
# Allow <iframe> and <embed> in addition to defaults
oakdom.xss.add-allowed-tags=iframe,embed

# Remove <strike> from the default allowed set
oakdom.xss.remove-allowed-tags=strike
```

### Allowed CSS properties

```properties
# Allow additional CSS properties
oakdom.xss.add-allowed-css-properties=position,z-index

# Remove a CSS property from the default allowed set
oakdom.xss.remove-allowed-css-properties=float
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

These can be explicitly added via `oakdom.xss.add-allowed-css-properties` if your application requires them and you accept the risk.

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
| `oakdom.xss.global-filter-mode` | ✅ |
| `oakdom.xss.filter-rules[n].url-pattern` (URL only) | ✅ |
| `oakdom.xss.filter-rules[n].param` | ❌ — param rules apply to query string / form data only |
| `oakdom.xss.filter-rules[n].url-pattern` + `param` | ❌ — param rules apply to query string / form data only |

To apply WHITELIST mode to a JSON body endpoint:

```properties
oakdom.xss.filter-rules[0].url-pattern=/api/editor/**
oakdom.xss.filter-rules[0].mode=WHITELIST
```

To skip JSON body sanitization for specific URLs:

```properties
oakdom.xss.exclude-urls=/api/raw/**
```

---

## Annotation-Based Control

Per-handler-method XSS control is available via annotations. Annotations take priority over configuration-based rules and are registered automatically — no additional setup required.

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

### DTO Field Annotations

For JSON request bodies, you can annotate individual fields of the DTO class to control filtering at the field level. This is the most granular level of control available.

```java
public class ArticleDto {

    // Raw value passes through — no XSS filtering applied to this field
    @OakdomXssExclude
    private String rawContent;

    // WHITELIST mode applied to this field, regardless of the body-level mode
    @OakdomXssFilterMode(FilterMode.WHITELIST)
    private String htmlBody;

    // No annotation — uses whatever mode is in effect for the body
    private String title;
}
```

Nested DTOs and collections are supported — annotations on nested DTO fields are applied recursively.

### JSON Body Behavior

- **DTO field `@OakdomXssExclude`** — that field passes through as-is; all other fields are still filtered.
- **DTO field `@OakdomXssFilterMode`** — that field uses the specified mode; all other fields use the body-level mode.
- **`@OakdomXssExclude` on `@RequestBody` or the handler method** — the entire body is skipped as-is. DTO field annotations are not consulted.
- **`@OakdomXssFilterMode` on `@RequestBody` or the handler method** — sets the default mode for the whole body. DTO field annotations can still override it per field.
- **`@RequestParam` annotations** have no effect on the JSON body.

### Priority

**For request parameters:**

| Priority | Source |
|----------|--------|
| 1 (highest) | Parameter-level annotation (`@RequestParam`) |
| 2 | Method-level annotation |
| 3 | Config rule — URL pattern + parameter name |
| 4 | Config rule — parameter name only |
| 5 | Config rule — URL pattern only |
| 6 (lowest) | Global filter mode |

**For JSON request body:**

| Priority | Source |
|----------|--------|
| 1 (highest) | DTO field annotation (`@OakdomXssExclude` / `@OakdomXssFilterMode` on the field) |
| 2 | `@RequestBody` parameter annotation |
| 3 | Method-level annotation |
| 4 | Config rule — URL pattern only |
| 5 (lowest) | Global filter mode |

> When `@OakdomXssExclude` is used at priority 2 or 3, the entire body is passed through as-is and DTO field annotations are not consulted. When `@OakdomXssFilterMode` is used at priority 2 or 3, it sets the default mode for the body and DTO field annotations (priority 1) can still override it per field.

---

## Disabling the Filter

```properties
oakdom.xss.enabled=false
```

---

## License

Apache License 2.0. See [LICENSE](../LICENSE) for details.
