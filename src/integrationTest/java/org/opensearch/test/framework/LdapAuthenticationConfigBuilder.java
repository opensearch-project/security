/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
* @param <T> is related to subclasses thus method defined in the class <code>LdapAuthenticationConfigBuilder</code> return proper subclass
*           type so that all method defined in subclass are available in one of builder superclass method is invoked. Please see
*           {@link LdapAuthorizationConfigBuilder}
*/
public class LdapAuthenticationConfigBuilder<T extends LdapAuthenticationConfigBuilder> {
    private boolean enableSsl = false;
    private boolean enableStartTls = false;
    private boolean enableSslClientAuth = false;
    private boolean verifyHostnames = false;
    private List<String> hosts;
    private String bindDn;
    private String password;
    private String userBase;
    private String userSearch;
    private String usernameAttribute;

    private String penTrustedCasFilePath;

    /**
    * Subclass of <code>this</code>
    */
    private final T builderSubclass;

    protected LdapAuthenticationConfigBuilder(Function<LdapAuthenticationConfigBuilder, T> thisCastFunction) {
        this.builderSubclass = thisCastFunction.apply(this);
    }

    public static LdapAuthenticationConfigBuilder<LdapAuthenticationConfigBuilder> config() {
        return new LdapAuthenticationConfigBuilder<>(Function.identity());
    }

    public T enableSsl(boolean enableSsl) {
        this.enableSsl = enableSsl;
        return builderSubclass;
    }

    public T enableStartTls(boolean enableStartTls) {
        this.enableStartTls = enableStartTls;
        return builderSubclass;
    }

    public T enableSslClientAuth(boolean enableSslClientAuth) {
        this.enableSslClientAuth = enableSslClientAuth;
        return builderSubclass;
    }

    public T verifyHostnames(boolean verifyHostnames) {
        this.verifyHostnames = verifyHostnames;
        return builderSubclass;
    }

    public T hosts(List<String> hosts) {
        this.hosts = hosts;
        return builderSubclass;
    }

    public T bindDn(String bindDn) {
        this.bindDn = bindDn;
        return builderSubclass;
    }

    public T password(String password) {
        this.password = password;
        return builderSubclass;
    }

    public T userBase(String userBase) {
        this.userBase = userBase;
        return builderSubclass;
    }

    public T userSearch(String userSearch) {
        this.userSearch = userSearch;
        return builderSubclass;
    }

    public T usernameAttribute(String usernameAttribute) {
        this.usernameAttribute = usernameAttribute;
        return builderSubclass;
    }

    public T penTrustedCasFilePath(String penTrustedCasFilePath) {
        this.penTrustedCasFilePath = penTrustedCasFilePath;
        return builderSubclass;
    }

    public Map<String, Object> build() {
        HashMap<String, Object> config = new HashMap<>();
        config.put("enable_ssl", enableSsl);
        config.put("enable_start_tls", enableStartTls);
        config.put("enable_ssl_client_auth", enableSslClientAuth);
        config.put("verify_hostnames", verifyHostnames);
        config.put("hosts", hosts);
        config.put("bind_dn", bindDn);
        config.put("password", password);
        config.put("userbase", userBase);
        config.put("usersearch", userSearch);
        config.put("username_attribute", usernameAttribute);
        config.put("pemtrustedcas_filepath", penTrustedCasFilePath);
        return config;
    }
}
