/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

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
