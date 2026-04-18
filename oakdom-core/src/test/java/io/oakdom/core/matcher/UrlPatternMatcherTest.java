package io.oakdom.core.matcher;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class UrlPatternMatcherTest {

    // -------------------------------------------------------------------------
    // Exact match
    // -------------------------------------------------------------------------

    @Test
    void exactMatch() {
        assertThat(matcher("/api/users").matches("/api/users")).isTrue();
    }

    @Test
    void exactMatch_differentPath_returnsFalse() {
        assertThat(matcher("/api/users").matches("/api/orders")).isFalse();
    }

    @Test
    void rootPath() {
        assertThat(matcher("/").matches("/")).isTrue();
    }

    // -------------------------------------------------------------------------
    // * wildcard (single segment)
    // -------------------------------------------------------------------------

    @Test
    void singleStar_matchesAnySingleSegment() {
        assertThat(matcher("/api/*").matches("/api/users")).isTrue();
    }

    @Test
    void singleStar_doesNotMatchMultipleSegments() {
        assertThat(matcher("/api/*").matches("/api/users/1")).isFalse();
    }

    @Test
    void singleStar_matchesEmptySegment() {
        assertThat(matcher("/api/*").matches("/api/")).isTrue();
    }

    @Test
    void singleStar_inMiddle() {
        assertThat(matcher("/api/*/profile").matches("/api/user/profile")).isTrue();
        assertThat(matcher("/api/*/profile").matches("/api/user/settings")).isFalse();
    }

    // -------------------------------------------------------------------------
    // ** wildcard (multiple segments)
    // -------------------------------------------------------------------------

    @Test
    void doubleStarAtEnd_matchesAnyDepth() {
        UrlPatternMatcher matcher = matcher("/api/**");
        assertThat(matcher.matches("/api/users")).isTrue();
        assertThat(matcher.matches("/api/users/1")).isTrue();
        assertThat(matcher.matches("/api/users/1/orders")).isTrue();
    }

    @Test
    void doubleStarAtEnd_matchesDirectChild() {
        assertThat(matcher("/api/**").matches("/api/users")).isTrue();
    }

    @Test
    void doubleStarAtEnd_doesNotMatchDifferentRoot() {
        assertThat(matcher("/api/**").matches("/admin/users")).isFalse();
    }

    @Test
    void doubleStarInMiddle() {
        UrlPatternMatcher matcher = matcher("/api/**/detail");
        assertThat(matcher.matches("/api/users/detail")).isTrue();
        assertThat(matcher.matches("/api/users/1/detail")).isTrue();
        assertThat(matcher.matches("/api/users/1/orders/detail")).isTrue();
        assertThat(matcher.matches("/api/users/1/orders")).isFalse();
    }

    // -------------------------------------------------------------------------
    // ? wildcard (single character)
    // -------------------------------------------------------------------------

    @Test
    void questionMark_matchesSingleChar() {
        assertThat(matcher("/api/v?").matches("/api/v1")).isTrue();
        assertThat(matcher("/api/v?").matches("/api/v2")).isTrue();
    }

    @Test
    void questionMark_doesNotMatchMultipleChars() {
        assertThat(matcher("/api/v?").matches("/api/v10")).isFalse();
    }

    @Test
    void questionMark_doesNotMatchEmpty() {
        assertThat(matcher("/api/v?").matches("/api/v")).isFalse();
    }

    // -------------------------------------------------------------------------
    // Multiple patterns
    // -------------------------------------------------------------------------

    @Test
    void multiplePatterns_matchesIfAnyMatches() {
        UrlPatternMatcher matcher = new UrlPatternMatcher(Arrays.asList("/api/**", "/admin/**"));
        assertThat(matcher.matches("/api/users")).isTrue();
        assertThat(matcher.matches("/admin/settings")).isTrue();
        assertThat(matcher.matches("/public/page")).isFalse();
    }

    @Test
    void emptyPatterns_neverMatches() {
        assertThat(new UrlPatternMatcher(Collections.emptyList()).matches("/api/users")).isFalse();
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private UrlPatternMatcher matcher(String pattern) {
        return new UrlPatternMatcher(Collections.singletonList(pattern));
    }
}
