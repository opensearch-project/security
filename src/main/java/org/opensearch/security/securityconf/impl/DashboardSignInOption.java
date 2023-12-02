package org.opensearch.security.securityconf.impl;

public enum DashboardSignInOption {
    BASIC("basic"),
    SAML("saml"),
    OPENID("openid"),
    ANONYMOUS("anonymous");

    private String option;

    DashboardSignInOption(String option) {
        this.option = option;
    }

    public String getOption() {
        return option;
    }
}
