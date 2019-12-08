/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.ldap.util;

public final class ConfigConstants {

    public static final String LDAP_AUTHC_USERBASE = "userbase";
    public static final String LDAP_AUTHC_USERNAME_ATTRIBUTE = "username_attribute";//multi-value
    public static final String LDAP_AUTHC_USERSEARCH = "usersearch";

    public static final String LDAP_AUTHCZ_USERS = "users";
    public static final String LDAP_AUTHZ_ROLES = "roles";
    public static final String LDAP_AUTHCZ_BASE = "base";
    public static final String LDAP_AUTHCZ_SEARCH = "search";


    public static final String LDAP_AUTHZ_RESOLVE_NESTED_ROLES = "resolve_nested_roles";
    public static final String LDAP_AUTHZ_ROLEBASE = "rolebase";
    public static final String LDAP_AUTHZ_ROLENAME = "rolename";//multi-value
    public static final String LDAP_AUTHZ_ROLESEARCH = "rolesearch";
    public static final String LDAP_AUTHZ_USERROLEATTRIBUTE = "userroleattribute";//multi-value
    public static final String LDAP_AUTHZ_USERROLENAME = "userrolename";//multi-value
    public static final String LDAP_AUTHZ_SKIP_USERS = "skip_users";
    public static final String LDAP_AUTHZ_ROLESEARCH_ENABLED = "rolesearch_enabled";
    public static final String LDAP_AUTHZ_NESTEDROLEFILTER = "nested_role_filter";
    public static final String LDAP_AUTHZ_MAX_NESTED_DEPTH = "max_nested_depth";
    public static final int LDAP_AUTHZ_MAX_NESTED_DEPTH_DEFAULT = 30;

    public static final String LDAP_HOSTS = "hosts";
    public static final String LDAP_BIND_DN = "bind_dn";
    public static final String LDAP_PASSWORD = "password";
    public static final String LDAP_FAKE_LOGIN_ENABLED = "fakelogin_enabled";
    public static final String LDAP_SEARCH_ALL_BASES = "search_all_bases";

    public static final String LDAP_FAKE_LOGIN_DN = "fakelogin_dn";
    public static final String LDAP_FAKE_LOGIN_PASSWORD = "fakelogin_password";

    public static final String LDAP_CONNECT_TIMEOUT = "connect_timeout"; // com.sun.jndi.ldap.connect.timeout
    public static final String LDAP_RESPONSE_TIMEOUT = "response_timeout"; // com.sun.jndi.ldap.read.timeout

    // ssl
    public static final String LDAPS_VERIFY_HOSTNAMES = "verify_hostnames";
    public static final String LDAPS_TRUST_ALL = "trust_all";
    public static final boolean LDAPS_VERIFY_HOSTNAMES_DEFAULT = true;
    public static final String LDAPS_ENABLE_SSL = "enable_ssl";
    public static final String LDAPS_ENABLE_START_TLS = "enable_start_tls";
    public static final String LDAPS_ENABLE_SSL_CLIENT_AUTH = "enable_ssl_client_auth";
    public static final boolean LDAPS_ENABLE_SSL_CLIENT_AUTH_DEFAULT = false;

    public static final String LDAPS_JKS_CERT_ALIAS = "cert_alias";
    public static final String LDAPS_JKS_TRUST_ALIAS = "ca_alias";

    public static final String LDAPS_PEMKEY_FILEPATH = "pemkey_filepath";
    public static final String LDAPS_PEMKEY_CONTENT = "pemkey_content";
    public static final String LDAPS_PEMKEY_PASSWORD = "pemkey_password";
    public static final String LDAPS_PEMCERT_FILEPATH = "pemcert_filepath";
    public static final String LDAPS_PEMCERT_CONTENT = "pemcert_content";
    public static final String LDAPS_PEMTRUSTEDCAS_FILEPATH = "pemtrustedcas_filepath";
    public static final String LDAPS_PEMTRUSTEDCAS_CONTENT = "pemtrustedcas_content";

    public static final String LDAPS_ENABLED_SSL_CIPHERS = "enabled_ssl_ciphers";
    public static final String LDAPS_ENABLED_SSL_PROTOCOLS = "enabled_ssl_protocols";

    // custom attributes
    public static final String LDAP_CUSTOM_ATTR_MAXVAL_LEN = "custom_attr_maxval_len";
    public static final String LDAP_CUSTOM_ATTR_WHITELIST = "custom_attr_whitelist";

    public static final String LDAP_CONNECTION_STRATEGY = "connection_strategy";

    public static final String LDAP_POOL_ENABLED = "pool.enabled";
    public static final String LDAP_POOL_MIN_SIZE = "pool.min_size";
    public static final String LDAP_POOL_MAX_SIZE = "pool.max_size";

    public static final String LDAP_POOL_TYPE = "pool.type";

    private ConfigConstants() {

    }

}
