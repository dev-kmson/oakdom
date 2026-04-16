package io.oakdom.xss.config;

public class XssConfig {

    private boolean enabled = true;
    private String filterMode = "blacklist";

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getFilterMode() {
        return filterMode;
    }

    public void setFilterMode(String filterMode) {
        this.filterMode = filterMode;
    }
}
