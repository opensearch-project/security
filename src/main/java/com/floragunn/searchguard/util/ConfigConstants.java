/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.util;

public final class ConfigConstants {

    public static final String DEFAULT_SECURITY_CONFIG_INDEX = "searchguard";
    public static final String SEARCHGUARD_ACTIONREQUESTFILTER = "searchguard.actionrequestfilter.names";
    public static final String SEARCHGUARD_ALLOW_ALL_FROM_LOOPBACK = "searchguard.allow_all_from_loopback";
    public static final String SEARCHGUARD_AUDITLOG_ENABLED = "searchguard.auditlog.enabled";
    public static final String SEARCHGUARD_TRANSPORT_AUTH_ENABLED = "searchguard.transport_auth.enabled";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHENTICATION_BACKEND = "searchguard.authentication.authentication_backend.impl";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHENTICATION_BACKEND_CACHE_ENABLE = "searchguard.authentication.authentication_backend.cache.enable";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_RESOLVE_NESTED_ROLES = "searchguard.authentication.authorization.ldap.resolve_nested_roles";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_ROLEBASE = "searchguard.authentication.authorization.ldap.rolebase";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_ROLENAME = "searchguard.authentication.authorization.ldap.rolename";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_ROLESEARCH = "searchguard.authentication.authorization.ldap.rolesearch";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLEATTRIBUTE = "searchguard.authentication.authorization.ldap.userroleattribute";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLENAME = "searchguard.authentication.authorization.ldap.userrolename";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHORIZATION_SETTINGSDB_ROLES = "searchguard.authentication.authorization.settingsdb.roles.";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHORIZER = "searchguard.authentication.authorizer.impl";
    public static final String SEARCHGUARD_AUTHENTICATION_AUTHORIZER_CACHE_ENABLE = "searchguard.authentication.authorizer.cache.enable";
    public static final String SEARCHGUARD_AUTHENTICATION_HTTP_AUTHENTICATOR = "searchguard.authentication.http_authenticator.impl";
    public static final String SEARCHGUARD_AUTHENTICATION_HTTPS_CLIENTCERT_ATTRIBUTENAME = "searchguard.authentication.https.clientcert.attributename";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_BIND_DN = "searchguard.authentication.ldap.bind_dn";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_HOST = "searchguard.authentication.ldap.host";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_LDAPS_SSL_ENABLED = "searchguard.authentication.ldap.ldaps.ssl.enabled";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_LDAPS_STARTTLS_ENABLED = "searchguard.authentication.ldap.ldaps.starttls.enabled";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_FILEPATH = "searchguard.authentication.ldap.ldaps.truststore_filepath";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_PASSWORD = "searchguard.authentication.ldap.ldaps.truststore_password";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_TYPE = "searchguard.authentication.ldap.ldaps.truststore_type";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_PASSWORD = "searchguard.authentication.ldap.password";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_USERBASE = "searchguard.authentication.ldap.userbase";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_USERNAME_ATTRIBUTE = "searchguard.authentication.ldap.username_attribute";
    public static final String SEARCHGUARD_AUTHENTICATION_LDAP_USERSEARCH = "searchguard.authentication.ldap.usersearch";
    public static final String SEARCHGUARD_AUTHENTICATION_PROXY_HEADER = "searchguard.authentication.proxy.header";
    public static final String SEARCHGUARD_AUTHENTICATION_PROXY_TRUSTED_IPS = "searchguard.authentication.proxy.trusted_ips";
    public static final String SEARCHGUARD_AUTHENTICATION_SETTINGSDB_DIGEST = "searchguard.authentication.settingsdb.digest";
    public static final String SEARCHGUARD_AUTHENTICATION_SETTINGSDB_USER = "searchguard.authentication.settingsdb.user.";
    public static final String SEARCHGUARD_AUTHENTICATION_SPNEGO_KRB5_CONFIG_FILEPATH = "searchguard.authentication.spnego.krb5_config_filepath";
    public static final String SEARCHGUARD_AUTHENTICATION_SPNEGO_LOGIN_CONFIG_FILEPATH = "searchguard.authentication.spnego.login_config_filepath";
    public static final String SEARCHGUARD_AUTHENTICATION_SPNEGO_LOGIN_CONFIG_NAME = "searchguard.authentication.spnego.login_config_name";
    public static final String SEARCHGUARD_AUTHENTICATION_SPNEGO_STRIP_REALM = "searchguard.authentication.spnego.strip_realm";
    public static final String SEARCHGUARD_AUTHENTICATION_WAFFLE_STRIP_DOMAIN = "searchguard.authentication.waffle.strip_domain";
    public static final String SEARCHGUARD_CHECK_FOR_ROOT = "searchguard.check_for_root";
    public static final String SEARCHGUARD_CONFIG_INDEX_NAME = "searchguard.config_index_name";
    public static final String SEARCHGUARD_DLSFILTER = "searchguard.dlsfilter.names";
    public static final String SEARCHGUARD_ENABLED = "searchguard.enabled";
    public static final String SEARCHGUARD_FLSFILTER = "searchguard.flsfilter.names";
    public static final String SEARCHGUARD_HTTP_ENABLE_SESSIONS = "searchguard.http.enable_sessions";
    public static final String SEARCHGUARD_HTTP_XFORWARDEDFOR_ENFORCE = "searchguard.http.xforwardedfor.enforce";
    public static final String SEARCHGUARD_HTTP_XFORWARDEDFOR_HEADER = "searchguard.http.xforwardedfor.header";
    public static final String SEARCHGUARD_HTTP_XFORWARDEDFOR_TRUSTEDPROXIES = "searchguard.http.xforwardedfor.trustedproxies";
    public static final String SEARCHGUARD_KEY_PATH = "searchguard.key_path";
    public static final String SEARCHGUARD_RESTACTIONFILTER = "searchguard.restactionfilter.names";
    public static final String SEARCHGUARD_REWRITE_GET_AS_SEARCH = "searchguard.rewrite_get_as_search";
    public static final String SEARCHGUARD_SSL_TRANSPORT_HTTP_ENABLED = "searchguard.ssl.transport.http.enabled";
    public static final String SEARCHGUARD_SSL_TRANSPORT_HTTP_ENFORCE_CLIENTAUTH = "searchguard.ssl.transport.http.enforce_clientauth";
    public static final String SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH = "searchguard.ssl.transport.http.keystore_filepath";
    public static final String SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_PASSWORD = "searchguard.ssl.transport.http.keystore_password";
    public static final String SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_TYPE = "searchguard.ssl.transport.http.keystore_type";
    public static final String SEARCHGUARD_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH = "searchguard.ssl.transport.http.truststore_filepath";
    public static final String SEARCHGUARD_SSL_TRANSPORT_HTTP_TRUSTSTORE_PASSWORD = "searchguard.ssl.transport.http.truststore_password";
    public static final String SEARCHGUARD_SSL_TRANSPORT_HTTP_TRUSTSTORE_TYPE = "searchguard.ssl.transport.http.truststore_type";
    public static final String SEARCHGUARD_SSL_TRANSPORT_NODE_ENABLED = "searchguard.ssl.transport.node.enabled";
    public static final String SEARCHGUARD_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION = "searchguard.ssl.transport.node.encforce_hostname_verification";
    public static final String SEARCHGUARD_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME = "searchguard.ssl.transport.node.encforce_hostname_verification.resolve_host_name";
    public static final String SEARCHGUARD_SSL_TRANSPORT_NODE_ENFORCE_CLIENTAUTH = "searchguard.ssl.transport.node.enforce_clientauth";
    public static final String SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH = "searchguard.ssl.transport.node.keystore_filepath";
    public static final String SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_PASSWORD = "searchguard.ssl.transport.node.keystore_password";
    public static final String SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_TYPE = "searchguard.ssl.transport.node.keystore_type";
    public static final String SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH = "searchguard.ssl.transport.node.truststore_filepath";
    public static final String SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_PASSWORD = "searchguard.ssl.transport.node.truststore_password";
    public static final String SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_TYPE = "searchguard.ssl.transport.node.truststore_type";
    public static final String SEARCHGUARD_WAFFLE_WINDOWS_AUTH_PROVIDER_IMPL = "searchguard.waffle.windows_auth_provider_impl";

    private ConfigConstants() {

    }

}
