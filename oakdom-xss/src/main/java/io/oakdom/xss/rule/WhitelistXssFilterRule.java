package io.oakdom.xss.rule;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * XSS filter rule that permits a predefined set of safe HTML tags and per-tag safe
 * attributes, while escaping everything else.
 *
 * <h2>Default allowed tags</h2>
 * <p>Inline: {@code b}, {@code i}, {@code em}, {@code strong}, {@code u}, {@code s},
 * {@code strike}, {@code small}, {@code sub}, {@code sup}, {@code cite}, {@code q},
 * {@code code}, {@code span}, {@code mark}, {@code abbr}, {@code del}, {@code ins},
 * {@code time}, {@code kbd}, {@code var}, {@code samp}, {@code wbr},
 * {@code ruby}, {@code rt}, {@code rp}, {@code bdi}, {@code bdo}, {@code dfn}.
 *
 * <p>Block: {@code p}, {@code div}, {@code h1}–{@code h6}, {@code blockquote},
 * {@code pre}, {@code ul}, {@code ol}, {@code li}, {@code dl}, {@code dt}, {@code dd},
 * {@code article}, {@code section}, {@code aside}, {@code header}, {@code footer},
 * {@code main}, {@code nav}, {@code address}, {@code details}, {@code summary},
 * {@code hgroup}, {@code meter}, {@code progress}.
 *
 * <p>Media: {@code a}, {@code img}, {@code picture}, {@code figure}, {@code figcaption},
 * {@code video}, {@code audio}, {@code source}, {@code track}.
 *
 * <p>Table: {@code table}, {@code thead}, {@code tbody}, {@code tfoot}, {@code tr},
 * {@code th}, {@code td}, {@code caption}, {@code col}, {@code colgroup}.
 *
 * <p>Other: {@code br}, {@code hr}.
 *
 * <h2>Global attributes</h2>
 * <p>The following attributes are permitted on every allowed tag:
 * {@code class}, {@code id}, {@code title}, {@code lang}, {@code dir}, {@code style}.
 * The {@code style} attribute is sanitized — only properties from the configured
 * CSS allowlist are kept, and dangerous patterns ({@code expression()},
 * {@code javascript:}, {@code vbscript:}, {@code behavior:}, {@code -moz-binding},
 * {@code @import}) are always removed. CSS custom properties
 * ({@code --*}) are always permitted regardless of the configured allowlist because
 * they cannot execute code; their values still pass the full dangerous-value and
 * URL checks. {@code url()} values inside any CSS property are validated against
 * the same URL allowlist used for {@code href} and {@code src}.
 *
 * <h2>Per-tag attributes</h2>
 * <ul>
 *   <li>{@code <a>} — {@code href}, {@code target}, {@code rel}, {@code title},
 *       {@code hreflang}, {@code type}, {@code referrerpolicy}.
 *       {@code href} accepts {@code https://}, {@code http://}, {@code //},
 *       {@code /}, {@code #}, {@code tel:}, {@code mailto:}, and scheme-less
 *       relative URLs. When {@code target="_blank"} is present, {@code noopener}
 *       and {@code noreferrer} are automatically appended to {@code rel} to prevent
 *       reverse tabnapping.</li>
 *   <li>{@code <abbr>} — {@code title}.</li>
 *   <li>{@code <blockquote>}, {@code <q>} — {@code cite}. URL allowlist applied.</li>
 *   <li>{@code <del>}, {@code <ins>}, {@code <time>} — {@code datetime}.</li>
 *   <li>{@code <details>} — {@code open}.</li>
 *   <li>{@code <img>} — {@code src}, {@code srcset}, {@code sizes}, {@code alt},
 *       {@code width}, {@code height}, {@code title}, {@code loading}, {@code decoding},
 *       {@code fetchpriority}, {@code crossorigin}, {@code referrerpolicy}.
 *       URL allowlist applied to {@code src}; each {@code srcset} entry is individually
 *       validated.</li>
 *   <li>{@code <video>} — {@code src}, {@code poster}, {@code controls},
 *       {@code autoplay}, {@code loop}, {@code muted}, {@code preload},
 *       {@code width}, {@code height}, {@code crossorigin}, {@code playsinline}.
 *       URL allowlist applied to {@code src} and {@code poster}.</li>
 *   <li>{@code <audio>} — {@code src}, {@code controls}, {@code autoplay},
 *       {@code loop}, {@code muted}, {@code preload}, {@code crossorigin}.
 *       URL allowlist applied to {@code src}.</li>
 *   <li>{@code <source>} — {@code src}, {@code srcset}, {@code media}, {@code sizes},
 *       {@code type}, {@code width}, {@code height}. URL allowlist applied to
 *       {@code src}; each {@code srcset} entry is individually validated.</li>
 *   <li>{@code <track>} — {@code src}, {@code kind}, {@code srclang}, {@code label},
 *       {@code default}. URL allowlist applied to {@code src}.</li>
 *   <li>{@code <ol>} — {@code start}, {@code type}, {@code reversed}.</li>
 *   <li>{@code <li>} — {@code value}.</li>
 *   <li>{@code <meter>} — {@code value}, {@code min}, {@code max}, {@code low},
 *       {@code high}, {@code optimum}.</li>
 *   <li>{@code <progress>} — {@code value}, {@code max}.</li>
 *   <li>{@code <th>} — {@code colspan}, {@code rowspan}, {@code scope},
 *       {@code align}, {@code valign}, {@code abbr}.</li>
 *   <li>{@code <td>} — {@code colspan}, {@code rowspan}, {@code align},
 *       {@code valign}.</li>
 *   <li>{@code <col>}, {@code <colgroup>} — {@code span}, {@code width}.</li>
 * </ul>
 *
 * <h2>Intentionally excluded</h2>
 * <p>The following are excluded for security reasons and will not be added to the
 * defaults:
 * <ul>
 *   <li>CSS {@code position}, {@code z-index}, {@code inset-*} — phishing overlay risk.</li>
 *   <li>CSS {@code mix-blend-mode} — overlay-based UI obscuring attacks.</li>
 *   <li>CSS {@code pointer-events} — clickjacking via UI element disabling.</li>
 *   <li>{@code <a download>} — drive-by file download (phishing).</li>
 * </ul>
 *
 * <h2>Customization</h2>
 * <p>Use {@link #WhitelistXssFilterRule(Set, Set, Set, Set)} to add or remove allowed
 * tags and CSS properties from the defaults. Disallowed tags and non-tag content are
 * always escaped using the full 7-character set
 * ({@code &}, {@code <}, {@code >}, {@code "}, {@code '}, {@code /}, {@code `}).
 *
 * <p>This rule is applied when the active {@link io.oakdom.core.filter.FilterMode} is
 * {@code WHITELIST}.
 */
public class WhitelistXssFilterRule implements XssFilterRule {

    /**
     * Default set of HTML tags permitted to pass through.
     */
    static final Set<String> DEFAULT_ALLOWED_TAGS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            // inline
            "b", "i", "em", "strong", "u", "s", "strike", "small", "sub", "sup",
            "cite", "q", "code", "span",
            "mark", "abbr", "del", "ins", "time",
            "kbd", "var", "samp", "wbr",
            "ruby", "rt", "rp",
            "bdi", "bdo", "dfn",
            // block
            "p", "div", "h1", "h2", "h3", "h4", "h5", "h6",
            "blockquote", "pre", "ul", "ol", "li", "dl", "dt", "dd",
            "article", "section", "aside", "header", "footer", "main", "nav", "address",
            "details", "summary", "hgroup",
            "meter", "progress",
            // media
            "a", "img", "picture", "figure", "figcaption",
            "video", "audio", "source", "track",
            // table
            "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "col", "colgroup",
            // other
            "br", "hr"
    )));

    /**
     * Attributes permitted on every allowed tag regardless of tag name.
     *
     * <p>{@code class} is safe as it only references CSS class names.
     * {@code style} is included but its value is sanitized by {@link #sanitizeCss(String)}
     * before being written to the output.
     */
    static final Set<String> GLOBAL_ALLOWED_ATTRIBUTES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("class", "style", "id", "lang", "dir", "title")));

    /**
     * Per-tag allowed attribute names, in addition to {@link #GLOBAL_ALLOWED_ATTRIBUTES}.
     */
    static final Map<String, Set<String>> ALLOWED_ATTRIBUTES;

    static {
        Map<String, Set<String>> map = new HashMap<>();
        map.put("a",         Collections.unmodifiableSet(new HashSet<>(Arrays.asList("href", "target", "rel", "title", "hreflang", "type", "referrerpolicy"))));
        map.put("blockquote", Collections.unmodifiableSet(new HashSet<>(Collections.singletonList("cite"))));
        map.put("q",         Collections.unmodifiableSet(new HashSet<>(Collections.singletonList("cite"))));
        map.put("abbr",      Collections.unmodifiableSet(new HashSet<>(Collections.singletonList("title"))));
        map.put("del",       Collections.unmodifiableSet(new HashSet<>(Collections.singletonList("datetime"))));
        map.put("ins",       Collections.unmodifiableSet(new HashSet<>(Collections.singletonList("datetime"))));
        map.put("time",      Collections.unmodifiableSet(new HashSet<>(Collections.singletonList("datetime"))));
        map.put("img",       Collections.unmodifiableSet(new HashSet<>(Arrays.asList("src", "srcset", "sizes", "alt", "width", "height", "title", "loading", "decoding", "fetchpriority", "crossorigin", "referrerpolicy"))));
        map.put("ol",        Collections.unmodifiableSet(new HashSet<>(Arrays.asList("start", "type", "reversed"))));
        map.put("meter",     Collections.unmodifiableSet(new HashSet<>(Arrays.asList("value", "min", "max", "low", "high", "optimum"))));
        map.put("progress",  Collections.unmodifiableSet(new HashSet<>(Arrays.asList("value", "max"))));
        map.put("li",        Collections.unmodifiableSet(new HashSet<>(Collections.singletonList("value"))));
        map.put("video",     Collections.unmodifiableSet(new HashSet<>(Arrays.asList("src", "poster", "controls", "autoplay", "loop", "muted", "preload", "width", "height", "crossorigin", "playsinline"))));
        map.put("audio",     Collections.unmodifiableSet(new HashSet<>(Arrays.asList("src", "controls", "autoplay", "loop", "muted", "preload", "crossorigin"))));
        map.put("source",    Collections.unmodifiableSet(new HashSet<>(Arrays.asList("src", "srcset", "media", "sizes", "type", "width", "height"))));
        map.put("details",   Collections.unmodifiableSet(new HashSet<>(Collections.singletonList("open"))));
        map.put("track",     Collections.unmodifiableSet(new HashSet<>(Arrays.asList("src", "kind", "srclang", "label", "default"))));
        map.put("th",        Collections.unmodifiableSet(new HashSet<>(Arrays.asList("colspan", "rowspan", "scope", "align", "valign", "abbr"))));
        map.put("td",        Collections.unmodifiableSet(new HashSet<>(Arrays.asList("colspan", "rowspan", "align", "valign"))));
        map.put("col",       Collections.unmodifiableSet(new HashSet<>(Arrays.asList("span", "width"))));
        map.put("colgroup",  Collections.unmodifiableSet(new HashSet<>(Arrays.asList("span", "width"))));
        ALLOWED_ATTRIBUTES = Collections.unmodifiableMap(map);
    }

    /**
     * Default set of CSS properties safe to allow in {@code style} attributes.
     *
     * <p>The set covers the following major categories:
     * <ul>
     *   <li><b>Color &amp; background</b> — {@code color}, {@code background},
     *       {@code background-color}, {@code background-image}, and all background
     *       longhands including {@code background-clip}, {@code background-blend-mode},
     *       and {@code -webkit-background-clip}.</li>
     *   <li><b>Typography</b> — all {@code font-*} longhands (including
     *       {@code font-variant-*}, {@code font-synthesis-*}, {@code font-optical-sizing},
     *       {@code font-palette}, {@code font-variation-settings}), all {@code text-*}
     *       longhands (including {@code text-decoration-*}, {@code text-emphasis-*},
     *       {@code text-wrap-*}, {@code text-box-*}), {@code line-height},
     *       {@code letter-spacing}, {@code word-spacing}, {@code white-space},
     *       {@code hyphens}, {@code direction}, {@code unicode-bidi},
     *       {@code writing-mode}, {@code ruby-*}, and vendor-prefixed smoothing
     *       ({@code -webkit-font-smoothing}, {@code -moz-osx-font-smoothing},
     *       {@code -webkit-text-stroke-*}, {@code -webkit-text-fill-color}).</li>
     *   <li><b>Box model</b> — {@code margin}, {@code padding}, and all physical and
     *       logical longhands ({@code margin-inline-*}, {@code padding-block-*},
     *       etc.).</li>
     *   <li><b>Border</b> — all physical and logical border longhands including
     *       {@code border-image-*}, {@code border-inline-*}, {@code border-block-*},
     *       and {@code border-*-radius} variants.</li>
     *   <li><b>Sizing &amp; display</b> — {@code width}, {@code height},
     *       {@code min-*}/{@code max-*}, logical sizes ({@code inline-size},
     *       {@code block-size}), {@code display}, {@code visibility}, {@code opacity},
     *       {@code float}, {@code clear}, {@code vertical-align}, {@code aspect-ratio},
     *       {@code object-fit}, {@code object-position}, {@code overflow} and longhands,
     *       {@code box-sizing}, {@code box-shadow}, {@code clip-path}.</li>
     *   <li><b>Flexbox</b> — {@code flex}, all {@code flex-*} longhands,
     *       {@code justify-content}/{@code justify-items}/{@code justify-self},
     *       {@code align-*}, {@code place-*}, {@code gap}, {@code order}.</li>
     *   <li><b>Grid</b> — {@code grid}, all {@code grid-template-*},
     *       {@code grid-column-*}/{@code grid-row-*}, {@code grid-auto-*},
     *       {@code grid-area}.</li>
     *   <li><b>Multi-column</b> — {@code columns}, {@code column-count},
     *       {@code column-width}, {@code column-rule-*}, {@code column-span},
     *       {@code column-fill}.</li>
     *   <li><b>Transform &amp; animation</b> — {@code transform} and all longhands
     *       ({@code rotate}, {@code scale}, {@code translate}, {@code transform-origin},
     *       {@code transform-style}, {@code perspective}, {@code perspective-origin},
     *       {@code backface-visibility}), {@code animation} and all longhands,
     *       {@code transition} and all longhands, {@code will-change},
     *       {@code offset-path} and longhands, {@code filter}, {@code backdrop-filter},
     *       {@code -webkit-backdrop-filter}.</li>
     *   <li><b>Scroll-driven animation</b> — {@code animation-timeline},
     *       {@code animation-range} and longhands, {@code scroll-timeline} and longhands,
     *       {@code view-timeline} and longhands.</li>
     *   <li><b>Scroll</b> — {@code scroll-behavior}, {@code scroll-snap-*},
     *       {@code scroll-padding-*}, {@code scroll-margin-*},
     *       {@code overscroll-behavior-*}, {@code scrollbar-width},
     *       {@code scrollbar-color}, {@code scrollbar-gutter}.</li>
     *   <li><b>UI &amp; interaction</b> — {@code cursor}, {@code resize},
     *       {@code accent-color}, {@code caret-color}, {@code appearance},
     *       {@code -webkit-appearance}, {@code user-select}, {@code touch-action},
     *       {@code -webkit-tap-highlight-color}, {@code -webkit-touch-callout}.</li>
     *   <li><b>Container queries</b> — {@code container}, {@code container-type},
     *       {@code container-name}, {@code content-visibility}, {@code contain},
     *       {@code contain-intrinsic-*}.</li>
     *   <li><b>Mask</b> — {@code mask} and all longhands, {@code mask-border} and
     *       all longhands, and {@code -webkit-mask-*} variants.</li>
     *   <li><b>SVG presentation</b> — {@code fill}, {@code fill-opacity},
     *       {@code fill-rule}, {@code stroke} and all longhands, {@code clip-rule},
     *       {@code paint-order}, {@code text-anchor}, {@code dominant-baseline},
     *       {@code alignment-baseline}, {@code baseline-shift}, {@code vector-effect},
     *       {@code shape-rendering}, {@code color-rendering},
     *       {@code color-interpolation-*}, {@code marker-*}, {@code stop-color},
     *       {@code stop-opacity}, {@code flood-color}, {@code flood-opacity},
     *       {@code lighting-color}, and geometry attributes
     *       ({@code d}, {@code cx}, {@code cy}, {@code r}, {@code rx}, {@code ry},
     *       {@code x}, {@code y}).</li>
     *   <li><b>Other</b> — {@code list-style-*}, {@code table-layout},
     *       {@code caption-side}, {@code empty-cells}, {@code quotes},
     *       {@code counter-reset}/{@code counter-increment}/{@code counter-set},
     *       {@code shape-outside}, {@code initial-letter}, {@code orphans},
     *       {@code widows}, {@code break-*}, {@code page-break-*},
     *       {@code print-color-adjust}, {@code color-scheme},
     *       {@code view-transition-name}, {@code forced-color-adjust},
     *       {@code isolation}, {@code zoom}, {@code interpolate-size},
     *       {@code image-rendering}, {@code image-orientation},
     *       {@code text-size-adjust}, {@code -webkit-text-size-adjust}.</li>
     * </ul>
     *
     * <p>{@code background-image} and any property accepting {@code url()} are included
     * because they may reference image URLs in editor-generated content. All
     * {@code url()} values are individually validated by {@link #isSafeUrl(String)}
     * before being accepted.
     *
     * <p>The following CSS properties are intentionally absent for security reasons:
     * {@code position}, {@code z-index}, {@code inset-*} (phishing overlay risk),
     * {@code mix-blend-mode} (UI obscuring), and {@code pointer-events} (clickjacking).
     */
    static final Set<String> DEFAULT_ALLOWED_CSS_PROPERTIES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "color", "background-color", "background", "background-image",
            "background-position", "background-size", "background-repeat", "background-attachment",
            "background-clip", "-webkit-background-clip", "background-origin",
            "background-position-x", "background-position-y",
            "background-blend-mode",
            "font", "font-size", "font-weight", "font-style", "font-family", "font-variant",
            "font-feature-settings", "font-stretch", "font-size-adjust",
            "font-optical-sizing", "font-kerning", "font-synthesis",
            "font-synthesis-weight", "font-synthesis-style", "font-synthesis-small-caps", "font-synthesis-position",
            "font-variant-ligatures", "font-variant-east-asian",
            "font-variant-alternates", "font-variant-position",
            "font-variation-settings", "font-palette",
            "text-align", "text-decoration", "text-transform", "text-indent", "text-overflow",
            "text-shadow",
            "text-decoration-color", "text-decoration-line", "text-decoration-style",
            "text-decoration-thickness", "text-underline-offset",
            "text-decoration-skip-ink", "text-underline-position",
            "text-emphasis", "text-emphasis-style", "text-emphasis-color", "text-emphasis-position",
            "line-height", "letter-spacing", "word-spacing", "white-space",
            "word-break", "overflow-wrap", "word-wrap",
            "hyphens", "tab-size", "text-wrap", "text-wrap-mode", "text-wrap-style",
            "white-space-collapse",
            "text-align-last", "text-justify",
            "line-break", "hyphenate-character", "hyphenate-limit-chars",
            "line-clamp", "-webkit-line-clamp", "-webkit-box-orient",
            "direction", "unicode-bidi", "writing-mode", "text-orientation", "text-combine-upright",
            "ruby-position", "ruby-align",
            "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
            "margin-inline", "margin-inline-start", "margin-inline-end",
            "margin-block", "margin-block-start", "margin-block-end",
            "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
            "padding-inline", "padding-inline-start", "padding-inline-end",
            "padding-block", "padding-block-start", "padding-block-end",
            "border", "border-top", "border-right", "border-bottom", "border-left",
            "border-color", "border-width", "border-style", "border-radius",
            "border-start-start-radius", "border-start-end-radius",
            "border-end-start-radius", "border-end-end-radius",
            "border-top-color", "border-right-color", "border-bottom-color", "border-left-color",
            "border-top-width", "border-right-width", "border-bottom-width", "border-left-width",
            "border-top-style", "border-right-style", "border-bottom-style", "border-left-style",
            "border-top-left-radius", "border-top-right-radius",
            "border-bottom-right-radius", "border-bottom-left-radius",
            "border-collapse", "border-spacing",
            "border-inline", "border-inline-start", "border-inline-end",
            "border-inline-color", "border-inline-start-color", "border-inline-end-color",
            "border-inline-width", "border-inline-start-width", "border-inline-end-width",
            "border-inline-style", "border-inline-start-style", "border-inline-end-style",
            "border-block", "border-block-start", "border-block-end",
            "border-block-color", "border-block-start-color", "border-block-end-color",
            "border-block-width", "border-block-start-width", "border-block-end-width",
            "border-block-style", "border-block-start-style", "border-block-end-style",
            "border-image", "border-image-source", "border-image-slice",
            "border-image-width", "border-image-outset", "border-image-repeat",
            "box-shadow", "box-sizing", "overflow", "overflow-x", "overflow-y", "overflow-clip-margin",
            "overflow-inline", "overflow-block", "overflow-anchor",
            "width", "height", "max-width", "max-height", "min-width", "min-height",
            "inline-size", "block-size", "min-inline-size", "max-inline-size", "min-block-size", "max-block-size",
            "display", "visibility", "opacity", "float", "clear", "vertical-align",
            "object-fit", "object-position", "aspect-ratio",
            "image-rendering", "image-orientation",
            "interpolate-size",
            "clip-path",
            "outline", "outline-color", "outline-width", "outline-style", "outline-offset",
            "transition", "transform", "filter",
            "rotate", "scale", "translate",
            "transform-origin", "transform-style", "perspective", "perspective-origin",
            "backface-visibility", "backdrop-filter", "-webkit-backdrop-filter",
            "offset-path", "offset-distance", "offset-rotate", "offset-anchor", "offset-position",
            "isolation",
            "will-change",
            "text-rendering", "-webkit-font-smoothing", "-moz-osx-font-smoothing",
            "-webkit-text-stroke", "-webkit-text-stroke-width", "-webkit-text-stroke-color",
            "-webkit-text-fill-color",
            "hanging-punctuation",
            "font-variant-numeric", "font-variant-caps",
            "animation", "animation-name", "animation-duration", "animation-timing-function",
            "animation-delay", "animation-iteration-count", "animation-direction",
            "animation-fill-mode", "animation-play-state", "animation-composition",
            "transition-property", "transition-duration", "transition-timing-function", "transition-delay",
            "transition-behavior",
            "animation-timeline", "animation-range", "animation-range-start", "animation-range-end",
            "scroll-timeline", "scroll-timeline-name", "scroll-timeline-axis",
            "view-timeline", "view-timeline-name", "view-timeline-axis", "view-timeline-inset",
            "zoom",
            "cursor", "resize",
            "accent-color", "caret-color",
            "appearance", "-webkit-appearance",
            "-webkit-tap-highlight-color", "-webkit-touch-callout",
            "scrollbar-width", "scrollbar-color", "scrollbar-gutter",
            "flex", "flex-direction", "flex-wrap", "flex-flow",
            "justify-content", "justify-items", "justify-self",
            "align-items", "align-content", "align-self",
            "place-items", "place-content", "place-self",
            "flex-grow", "flex-shrink", "flex-basis", "order",
            "gap", "row-gap", "column-gap",
            "grid", "grid-template", "grid-template-columns", "grid-template-rows",
            "grid-template-areas", "grid-column", "grid-row", "grid-area",
            "grid-auto-flow", "grid-auto-columns", "grid-auto-rows",
            "grid-column-start", "grid-column-end", "grid-row-start", "grid-row-end",
            "column-count", "column-width", "columns", "column-rule",
            "column-rule-color", "column-rule-style", "column-rule-width",
            "column-span", "column-fill",
            "touch-action",
            "user-select", "-webkit-user-select", "scroll-behavior",
            "scroll-snap-type", "scroll-snap-align", "scroll-snap-stop",
            "scroll-padding", "scroll-padding-top", "scroll-padding-right", "scroll-padding-bottom", "scroll-padding-left",
            "scroll-padding-inline", "scroll-padding-inline-start", "scroll-padding-inline-end",
            "scroll-padding-block", "scroll-padding-block-start", "scroll-padding-block-end",
            "scroll-margin", "scroll-margin-top", "scroll-margin-right", "scroll-margin-bottom", "scroll-margin-left",
            "scroll-margin-inline", "scroll-margin-inline-start", "scroll-margin-inline-end",
            "scroll-margin-block", "scroll-margin-block-start", "scroll-margin-block-end",
            "overscroll-behavior", "overscroll-behavior-x", "overscroll-behavior-y",
            "overscroll-behavior-block", "overscroll-behavior-inline",
            "text-size-adjust", "-webkit-text-size-adjust",
            "color-scheme",
            "break-before", "break-after", "break-inside",
            "page-break-before", "page-break-after", "page-break-inside",
            "print-color-adjust", "-webkit-print-color-adjust",
            "shape-outside", "shape-margin", "shape-image-threshold",
            "table-layout", "caption-side", "empty-cells",
            "list-style-type", "list-style-position", "list-style", "list-style-image",
            "quotes",
            "initial-letter",
            "counter-reset", "counter-increment", "counter-set",
            "container", "container-type", "container-name",
            "content-visibility", "contain",
            "contain-intrinsic-size", "contain-intrinsic-width", "contain-intrinsic-height",
            "contain-intrinsic-inline-size", "contain-intrinsic-block-size",
            "view-transition-name",
            "mask", "mask-image", "mask-size", "mask-repeat", "mask-position",
            "mask-clip", "mask-mode", "mask-composite", "mask-origin",
            "mask-position-x", "mask-position-y",
            "mask-border", "mask-border-source", "mask-border-slice",
            "mask-border-width", "mask-border-outset", "mask-border-repeat", "mask-border-mode",
            "-webkit-mask-image", "-webkit-mask-size", "-webkit-mask-repeat", "-webkit-mask-position",
            "-webkit-mask-clip", "-webkit-mask-origin", "-webkit-mask-composite",
            "orphans", "widows",
            "forced-color-adjust",
            "fill", "fill-opacity", "fill-rule",
            "stroke", "stroke-opacity", "stroke-width",
            "stroke-linecap", "stroke-linejoin", "stroke-miterlimit",
            "stroke-dasharray", "stroke-dashoffset",
            "clip-rule", "paint-order",
            "text-anchor", "dominant-baseline", "alignment-baseline", "baseline-shift",
            "vector-effect", "shape-rendering", "color-rendering", "color-interpolation", "color-interpolation-filters",
            "text-box", "text-box-trim", "text-box-edge",
            "marker", "marker-start", "marker-mid", "marker-end",
            "stop-color", "stop-opacity",
            "flood-color", "flood-opacity", "lighting-color",
            "d", "cx", "cy", "r", "rx", "ry", "x", "y"
    )));

    /**
     * Attribute names whose values must pass URL safety validation before being allowed.
     */
    private static final Set<String> URL_ATTRIBUTES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("href", "src", "poster", "cite")));

    /**
     * Attribute names that contain a comma-separated list of URLs with optional descriptors
     * (e.g., {@code srcset="img.jpg 1x, img@2x.jpg 2x"}). Each URL is individually validated
     * by {@link #isSafeUrl(String)}; unsafe entries are dropped while safe ones are preserved.
     */
    private static final Set<String> SRCSET_ATTRIBUTES = Collections.unmodifiableSet(
            new HashSet<>(Collections.singletonList("srcset")));

    /**
     * Matches an HTML opening or closing tag, capturing the optional closing slash,
     * the tag name, and any attribute string.
     */
    private static final Pattern TAG_PATTERN = Pattern.compile(
            "<(/?)([a-zA-Z][a-zA-Z0-9]*)(\\s+(?:\"[^\"]*\"|'[^']*'|[^>\"'])*)?\\s*/?>",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Matches a single HTML attribute, capturing the name and value (double-quoted,
     * single-quoted, or unquoted).
     */
    private static final Pattern ATTR_PATTERN = Pattern.compile(
            "([a-zA-Z][a-zA-Z0-9-]*)\\s*(?:=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]*)))?",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Matches a single CSS declaration ({@code property: value}).
     */
    private static final Pattern CSS_PROPERTY_PATTERN = Pattern.compile(
            "([a-zA-Z-]+)\\s*:\\s*([^;]+)",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Matches known dangerous CSS value patterns that can execute scripts.
     *
     * <p>{@code url()} is intentionally excluded from this pattern; instead, the URL
     * inside {@code url()} is extracted and validated individually by
     * {@link #isSafeUrl(String)}.
     */
    private static final Pattern DANGEROUS_CSS_VALUE = Pattern.compile(
            "expression\\s*\\(|javascript\\s*:|vbscript\\s*:|behavior\\s*:|-moz-binding|@import",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Matches a CSS unicode escape sequence: a backslash followed by 1–6 hex digits,
     * optionally followed by a single whitespace character (which is consumed as part of
     * the escape per the CSS specification).
     */
    private static final Pattern CSS_UNICODE_ESCAPE = Pattern.compile(
            "\\\\([0-9a-fA-F]{1,6})[ \\t\\r\\n\\f]?"
    );

    /**
     * Extracts the URL value from a CSS {@code url()} function.
     * Supports double-quoted, single-quoted, and unquoted URL values.
     */
    private static final Pattern CSS_URL_PATTERN = Pattern.compile(
            "url\\s*\\(\\s*['\"]?([^'\"\\)\\s]+)['\"]?\\s*\\)",
            Pattern.CASE_INSENSITIVE
    );

    private final Set<String> allowedTags;
    private final Set<String> allowedCssProperties;

    /**
     * Creates a rule using the default allowed tags and CSS properties.
     */
    public WhitelistXssFilterRule() {
        this.allowedTags = DEFAULT_ALLOWED_TAGS;
        this.allowedCssProperties = DEFAULT_ALLOWED_CSS_PROPERTIES;
    }

    /**
     * Creates a rule starting from the defaults and applying the given additions and removals.
     *
     * <p>Tag and property names are normalized to lowercase before comparison.
     *
     * @param addAllowedTags           tags to add to the default allowed set; may be {@code null} or empty
     * @param removeAllowedTags        tags to remove from the default allowed set; may be {@code null} or empty
     * @param addAllowedCssProperties  CSS properties to add to the default allowed set; may be {@code null} or empty
     * @param removeAllowedCssProperties CSS properties to remove from the default allowed set; may be {@code null} or empty
     */
    public WhitelistXssFilterRule(Set<String> addAllowedTags, Set<String> removeAllowedTags,
                                   Set<String> addAllowedCssProperties, Set<String> removeAllowedCssProperties) {
        this.allowedTags = buildEffectiveSet(DEFAULT_ALLOWED_TAGS, addAllowedTags, removeAllowedTags);
        this.allowedCssProperties = buildEffectiveSet(DEFAULT_ALLOWED_CSS_PROPERTIES, addAllowedCssProperties, removeAllowedCssProperties);
    }

    private static Set<String> buildEffectiveSet(Set<String> defaults, Set<String> toAdd, Set<String> toRemove) {
        if ((toAdd == null || toAdd.isEmpty()) && (toRemove == null || toRemove.isEmpty())) {
            return defaults;
        }
        Set<String> effective = new HashSet<>(defaults);
        if (toRemove != null) {
            effective.removeAll(toRemove);
        }
        if (toAdd != null) {
            effective.addAll(toAdd);
        }
        return Collections.unmodifiableSet(effective);
    }

    /**
     * Applies the whitelist rule to the given value.
     *
     * <p>Allowed tags are preserved with only their permitted attributes. All other tags
     * and HTML-significant characters in non-tag content are escaped.
     *
     * @param value the raw input value; may be {@code null}
     * @return the sanitized value, or {@code null} if {@code value} is {@code null}
     */
    @Override
    public String apply(String value) {
        if (value == null) {
            return null;
        }

        StringBuilder result = new StringBuilder(value.length());
        Matcher matcher = TAG_PATTERN.matcher(value);
        int lastEnd = 0;

        while (matcher.find()) {
            result.append(escapeHtml(value.substring(lastEnd, matcher.start())));

            String closing = matcher.group(1);
            String tagName = matcher.group(2).toLowerCase();
            String attributes = matcher.group(3);

            if (allowedTags.contains(tagName)) {
                if (closing.isEmpty()) {
                    String safeAttrs = buildSafeAttributes(tagName, attributes);
                    result.append('<').append(tagName).append(safeAttrs).append('>');
                } else {
                    result.append("</").append(tagName).append('>');
                }
            } else {
                result.append(escapeHtml(matcher.group(0)));
            }

            lastEnd = matcher.end();
        }

        result.append(escapeHtml(value.substring(lastEnd)));

        return result.toString();
    }

    /**
     * Builds a safe attribute string for the given tag by retaining only allowed
     * attributes, rejecting unsafe URL values, and sanitizing {@code style} values.
     *
     * @param tagName    the lowercase tag name
     * @param attributes the raw attribute string from the matched tag, or {@code null}
     * @return a safe attribute string (may be empty), ready to append after the tag name
     */
    private String buildSafeAttributes(String tagName, String attributes) {
        if (attributes == null || attributes.trim().isEmpty()) {
            return "";
        }

        Set<String> allowedAttrs = ALLOWED_ATTRIBUTES.get(tagName);
        StringBuilder safeAttrs = new StringBuilder();
        Matcher attrMatcher = ATTR_PATTERN.matcher(attributes);

        // For <a> tags: defer rel output so noopener/noreferrer can be enforced after
        // we know whether target="_blank" is present.
        boolean isAnchor = "a".equals(tagName);
        String anchorTargetValue = null;
        String anchorRelValue = null;

        while (attrMatcher.find()) {
            String attrName = attrMatcher.group(1).toLowerCase();
            if (!GLOBAL_ALLOWED_ATTRIBUTES.contains(attrName)
                    && (allowedAttrs == null || !allowedAttrs.contains(attrName))) {
                continue;
            }

            String attrValue = attrMatcher.group(2) != null ? attrMatcher.group(2)
                    : attrMatcher.group(3) != null ? attrMatcher.group(3)
                    : attrMatcher.group(4) != null ? attrMatcher.group(4)
                    : "";

            // Defer rel for <a> — it is output after the loop once we know target's value.
            if (isAnchor && "rel".equals(attrName)) {
                anchorRelValue = attrValue;
                continue;
            }
            // Track target value so we can enforce rel="noopener noreferrer" below.
            if (isAnchor && "target".equals(attrName)) {
                anchorTargetValue = attrValue;
            }

            if (URL_ATTRIBUTES.contains(attrName)) {
                if (!isSafeUrl(attrValue)) {
                    continue;
                }
                safeAttrs.append(' ').append(attrName).append("=\"")
                        .append(escapeHtmlAttr(attrValue)).append('"');
            } else if (SRCSET_ATTRIBUTES.contains(attrName)) {
                String safeSrcset = sanitizeSrcset(attrValue);
                if (!safeSrcset.isEmpty()) {
                    safeAttrs.append(' ').append(attrName).append("=\"")
                            .append(escapeHtmlAttr(safeSrcset)).append('"');
                }
            } else if ("style".equals(attrName)) {
                String safeCss = sanitizeCss(attrValue);
                if (!safeCss.isEmpty()) {
                    safeAttrs.append(' ').append("style").append("=\"")
                            .append(escapeHtmlAttr(safeCss)).append('"');
                }
            } else {
                safeAttrs.append(' ').append(attrName).append("=\"")
                        .append(escapeHtmlAttr(attrValue)).append('"');
            }
        }

        // Output rel for <a> tags. If target="_blank", enforce noopener + noreferrer
        // to prevent reverse tabnapping (window.opener access from the opened tab).
        if (isAnchor) {
            if ("_blank".equalsIgnoreCase(anchorTargetValue)) {
                String safeRel = enforceNoopenerRel(anchorRelValue);
                safeAttrs.append(' ').append("rel").append("=\"")
                        .append(escapeHtmlAttr(safeRel)).append('"');
            } else if (anchorRelValue != null) {
                safeAttrs.append(' ').append("rel").append("=\"")
                        .append(escapeHtmlAttr(anchorRelValue)).append('"');
            }
        }

        return safeAttrs.toString();
    }

    /**
     * Sanitizes a CSS {@code style} attribute value by allowing only properties in the
     * configured allowed CSS property set whose values are free of dangerous patterns.
     *
     * <p>Each CSS declaration is parsed individually. A declaration is dropped if:
     * <ul>
     *   <li>its property name is not in the allowed CSS property set and is not a CSS
     *       custom property (i.e., does not start with {@code --});</li>
     *   <li>its value matches {@link #DANGEROUS_CSS_VALUE}; or</li>
     *   <li>it contains a {@code url()} whose extracted URL does not pass
     *       {@link #isSafeUrl(String)}.</li>
     * </ul>
     *
     * <p>CSS custom properties ({@code --*}) are always permitted regardless of the
     * configured allowed set because they cannot execute code and are widely used for
     * theming. Their names are preserved with their original casing because CSS custom
     * properties are case-sensitive ({@code --MyColor} and {@code --mycolor} are distinct).
     * Their values still pass through the full dangerous-value and URL checks.
     *
     * @param style the raw {@code style} attribute value
     * @return a sanitized CSS string containing only safe declarations; never {@code null}
     */
    private String sanitizeCss(String style) {
        if (style == null || style.trim().isEmpty()) {
            return "";
        }

        // Strip CSS comments before analysis to prevent bypass via comment injection.
        // For example, "exp/**/ression(alert(1))" must be treated as "expression(alert(1))".
        style = style.replaceAll("(?s)/\\*.*?\\*/", "");
        if (style.trim().isEmpty()) {
            return "";
        }

        // Strip null bytes — some browsers treat them as ignored characters in CSS,
        // which can be used to split dangerous keywords (e.g., "exp\0ression").
        style = style.replace("\0", "");

        // Decode CSS unicode escapes — browsers resolve \HHHHHH escapes before applying CSS,
        // so "e" can be written as "\65 " and "expression" becomes "\65xpression".
        // Decoding here ensures the DANGEROUS_CSS_VALUE pattern sees the real text.
        style = decodeCssUnicodeEscapes(style);

        // Re-strip null bytes that may have been introduced by decoding a \000000 escape
        // (codepoint 0). A decoded null char is not caught by the earlier strip because
        // it did not exist as a literal character until after the unicode decode step.
        style = style.replace("\0", "");

        StringBuilder safe = new StringBuilder();
        Matcher matcher = CSS_PROPERTY_PATTERN.matcher(style);

        while (matcher.find()) {
            String rawProperty = matcher.group(1).trim();
            String property = rawProperty.toLowerCase();
            String cssValue = matcher.group(2).trim();

            // CSS custom properties (--*) are always permitted — they cannot execute code.
            // Their names preserve original casing because CSS custom properties are case-sensitive.
            boolean isCustomProperty = rawProperty.startsWith("--");
            if (!isCustomProperty && !allowedCssProperties.contains(property)) {
                continue;
            }
            if (DANGEROUS_CSS_VALUE.matcher(cssValue).find()) {
                continue;
            }

            boolean hasUnsafeUrl = false;
            Matcher urlMatcher = CSS_URL_PATTERN.matcher(cssValue);
            while (urlMatcher.find()) {
                if (!isSafeUrl(urlMatcher.group(1))) {
                    hasUnsafeUrl = true;
                    break;
                }
            }
            if (hasUnsafeUrl) {
                continue;
            }

            if (safe.length() > 0) {
                safe.append(' ');
            }
            // Preserve original casing for custom properties; normalize standard ones to lowercase.
            safe.append(isCustomProperty ? rawProperty : property).append(": ").append(cssValue).append(';');
        }

        return safe.toString();
    }

    /**
     * Sanitizes a {@code srcset} attribute value by validating each comma-separated URL
     * entry individually. Entries whose URL does not pass {@link #isSafeUrl(String)} are
     * silently dropped; safe entries are reassembled in their original order.
     *
     * <p>Each entry has the form {@code url descriptor} where the descriptor (e.g.,
     * {@code 2x} or {@code 480w}) is optional. Only the URL portion is validated.
     *
     * @param srcset the raw {@code srcset} attribute value
     * @return a sanitized srcset string containing only safe entries; never {@code null}
     */
    private String sanitizeSrcset(String srcset) {
        if (srcset == null || srcset.trim().isEmpty()) {
            return "";
        }
        StringBuilder safe = new StringBuilder();
        for (String entry : srcset.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            // The URL is the first whitespace-delimited token; the rest are descriptors.
            int spaceIdx = trimmed.indexOf(' ');
            String url = spaceIdx < 0 ? trimmed : trimmed.substring(0, spaceIdx);
            if (isSafeUrl(url)) {
                if (safe.length() > 0) {
                    safe.append(", ");
                }
                safe.append(trimmed);
            }
        }
        return safe.toString();
    }

    /**
     * Ensures that {@code noopener} and {@code noreferrer} are present in the given
     * {@code rel} value. If {@code existingRel} is {@code null} or blank, returns
     * {@code "noopener noreferrer"}. Otherwise, appends the missing tokens to the end
     * of the existing value while preserving other tokens such as {@code nofollow}.
     *
     * @param existingRel the original {@code rel} attribute value, or {@code null}
     * @return a {@code rel} value that contains at least {@code noopener} and
     *         {@code noreferrer}
     */
    private static String enforceNoopenerRel(String existingRel) {
        if (existingRel == null || existingRel.trim().isEmpty()) {
            return "noopener noreferrer";
        }
        boolean hasNoopener = false;
        boolean hasNoreferrer = false;
        for (String token : existingRel.trim().split("\\s+")) {
            if ("noopener".equals(token.toLowerCase())) {
                hasNoopener = true;
            }
            if ("noreferrer".equals(token.toLowerCase())) {
                hasNoreferrer = true;
            }
        }
        StringBuilder rel = new StringBuilder(existingRel.trim());
        if (!hasNoopener) {
            rel.append(" noopener");
        }
        if (!hasNoreferrer) {
            rel.append(" noreferrer");
        }
        return rel.toString();
    }

    /**
     * Returns {@code true} if the given URL value is safe to use in an HTML attribute.
     *
     * <p>Only the following URL forms are permitted (allowlist approach):
     * <ul>
     *   <li>{@code https://} — absolute HTTPS URL</li>
     *   <li>{@code http://} — absolute HTTP URL</li>
     *   <li>{@code //} — protocol-relative URL</li>
     *   <li>{@code /} — absolute path</li>
     *   <li>{@code #} — fragment (anchor)</li>
     *   <li>{@code tel:} — telephone link</li>
     *   <li>{@code mailto:} — email link</li>
     *   <li>No scheme (relative URL not containing {@code :}) — relative path</li>
     * </ul>
     *
     * <p>All other values, including {@code javascript:}, {@code vbscript:},
     * {@code data:}, and encoding-based variants such as {@code javascript&#58;alert(1)}
     * or {@code javascript%3aalert(1)}, are rejected.
     *
     * <p>Common encodings of the colon character are normalized before the scheme check
     * to prevent protocol-injection bypass via HTML entity or URL percent encoding.
     * Normalized forms include decimal entities with optional leading zeros
     * ({@code &#58;}, {@code &#058;}, {@code &#0058;}, …), hex entities with optional
     * leading zeros ({@code &#x3a;}, {@code &#x03a;}, {@code &#x003a;}, …), the HTML5
     * named entity ({@code &colon;}), and percent-encoded colon ({@code %3a}, {@code %3A}).
     *
     * @param url the raw URL value to validate
     * @return {@code true} if the URL is safe; {@code false} otherwise
     */
    private boolean isSafeUrl(String url) {
        String trimmed = url.trim().toLowerCase()
                // Decimal numeric entity: &#58; &#058; &#0058; etc. (leading zeros allowed by HTML5)
                .replaceAll("&#0*58;", ":")
                // Hex numeric entity: &#x3a; &#x03a; &#x003a; etc. (leading zeros allowed by HTML5)
                .replaceAll("&#x0*3a;", ":")
                // HTML5 named entity for colon
                .replace("&colon;", ":")
                // Percent-encoded colon: %3a (toLowerCase already normalises %3A → %3a)
                .replace("%3a", ":");
        // Raw '<' or '>' are never valid in a URL — reject immediately to prevent
        // HTML injection through values that slipped past split-based parsing (e.g.,
        // a data URI with embedded HTML that was split at an internal comma in srcset).
        if (trimmed.contains("<") || trimmed.contains(">")) {
            return false;
        }
        return trimmed.startsWith("https://")
                || trimmed.startsWith("http://")
                || trimmed.startsWith("//")
                || trimmed.startsWith("/")
                || trimmed.startsWith("#")
                || trimmed.startsWith("tel:")
                || trimmed.startsWith("mailto:")
                || !trimmed.contains(":");
    }

    /**
     * Decodes CSS unicode escape sequences of the form {@code \HHHHHH} (1–6 hex digits),
     * optionally followed by a single whitespace character that is consumed as part of
     * the escape per the CSS specification.
     *
     * <p>This normalisation is applied before danger-pattern matching so that obfuscated
     * values such as {@code \65xpression(alert(1))} (where {@code \65} = {@code 'e'}) are
     * detected correctly.
     *
     * <p>Escape sequences that decode to an invalid Unicode codepoint (above
     * {@code U+10FFFF}) are silently dropped to prevent {@link IllegalArgumentException}
     * from {@link Character#toChars(int)}.
     *
     * @param css raw CSS value string
     * @return the same string with all unicode escapes replaced by their actual characters
     */
    private static String decodeCssUnicodeEscapes(String css) {
        Matcher m = CSS_UNICODE_ESCAPE.matcher(css);
        StringBuffer sb = new StringBuffer(css.length());
        while (m.find()) {
            int codePoint = Integer.parseInt(m.group(1), 16);
            // Silently drop escapes that map to an invalid Unicode codepoint (above U+10FFFF).
            // Character.toChars() would throw IllegalArgumentException for such values.
            if (!Character.isValidCodePoint(codePoint)) {
                m.appendReplacement(sb, "");
                continue;
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(new String(Character.toChars(codePoint))));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Escapes HTML-significant characters in a plain-text segment or a disallowed tag.
     * Uses the full 7-character set, including {@code /} and {@code `}, so that
     * disallowed closing tags such as {@code </script>} are rendered inert.
     *
     * @param text the text segment to escape
     * @return the escaped text
     */
    private String escapeHtml(String text) {
        return text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;")
                .replace("`", "&#x60;");
    }

    /**
     * Escapes HTML-significant characters in an attribute value that is already enclosed
     * in double quotes. Does <em>not</em> escape {@code /} so that URL values such as
     * {@code https://example.com/path} remain valid after output.
     *
     * @param text the attribute value to escape
     * @return the escaped attribute value
     */
    private String escapeHtmlAttr(String text) {
        return text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("`", "&#x60;");
    }
}
