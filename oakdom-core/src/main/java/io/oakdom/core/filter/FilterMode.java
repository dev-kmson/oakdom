package io.oakdom.core.filter;

/**
 * Defines the filtering strategy applied during sanitization.
 *
 * <ul>
 *   <li>{@link #BLACKLIST} - escapes known dangerous patterns; everything else passes through.</li>
 *   <li>{@link #WHITELIST} - escapes everything except explicitly allowed patterns.</li>
 * </ul>
 */
public enum FilterMode {

    /**
     * Escapes known dangerous patterns and allows everything else.
     * This is the default mode.
     */
    BLACKLIST,

    /**
     * Escapes all input except explicitly allowed patterns (e.g., safe HTML tags).
     */
    WHITELIST
}
