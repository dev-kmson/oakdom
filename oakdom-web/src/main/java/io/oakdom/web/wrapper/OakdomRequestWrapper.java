package io.oakdom.web.wrapper;

import io.oakdom.core.filter.FilterMode;

public abstract class OakdomRequestWrapper {

    public abstract String sanitizeValue(String value, FilterMode filterMode);

    public abstract boolean isExcluded(String parameterName);
}
