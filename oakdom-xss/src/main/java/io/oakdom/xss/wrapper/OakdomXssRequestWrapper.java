package io.oakdom.xss.wrapper;

import io.oakdom.core.filter.FilterMode;
import io.oakdom.web.wrapper.OakdomRequestWrapper;

public class OakdomXssRequestWrapper extends OakdomRequestWrapper {

    @Override
    public String sanitizeValue(String value, FilterMode filterMode) {
        return value;
    }

    @Override
    public boolean isExcluded(String parameterName) {
        return false;
    }
}
