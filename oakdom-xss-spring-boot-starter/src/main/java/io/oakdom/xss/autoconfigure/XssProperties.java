package io.oakdom.xss.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "oakdom.xss")
public class XssProperties {

    private boolean enabled = true;
    private String filterMode = "blacklist";
    private List<String> excludeUrls = new ArrayList<String>();
    private List<String> excludeParameters = new ArrayList<String>();

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

    public List<String> getExcludeUrls() {
        return excludeUrls;
    }

    public void setExcludeUrls(List<String> excludeUrls) {
        this.excludeUrls = excludeUrls;
    }

    public List<String> getExcludeParameters() {
        return excludeParameters;
    }

    public void setExcludeParameters(List<String> excludeParameters) {
        this.excludeParameters = excludeParameters;
    }
}
