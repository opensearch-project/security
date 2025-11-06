/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.http;

import java.nio.file.Path;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.Nullable;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.Strings;
import org.opensearch.security.auth.HTTPAuthenticator;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityResponse;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.AuthCredentials;

public class HTTPClientCertAuthenticator implements HTTPAuthenticator {

    protected final Logger log = LogManager.getLogger(this.getClass());
    public static final String OPENDISTRO_SECURITY_SSL_SKIP_USERS = "skip_users";
    protected final Settings settings;
    private final WildcardMatcher skipUsersMatcher;
    private final ParsedAttribute parsedUsernameAttr;
    private final ParsedAttribute parsedRolesAttr;

    private enum AttributeType {
        DN,
        SAN
    }

    private record ParsedSAN(int type, @Nullable WildcardMatcher matcher) {
    }

    private record ParsedAttribute(AttributeType type, String dnAttr, ParsedSAN san) {

        static ParsedAttribute dn(String dnAttr) {
            return new ParsedAttribute(AttributeType.DN, dnAttr, null);
        }

        static ParsedAttribute san(ParsedSAN san) {
            return new ParsedAttribute(AttributeType.SAN, null, san);
        }
    }

    // Accept forms:
    // "cn" -> DN:cn
    // "dn:cn" -> DN:cn
    // "san:EMAIL" -> SAN type EMAIL, no glob (match all of that SAN)
    // "san:EMAIL:glob" -> SAN type EMAIL, glob
    private ParsedAttribute parseAttributeSetting(String raw) {
        if (Strings.isNullOrEmpty(raw)) return null; // “not configured”
        final String s = raw.trim();

        // SAN form: san:TYPE[:glob]
        if (s.regionMatches(true, 0, "san:", 0, 4)) {
            final String rest = s.substring(4); // after "san:"
            final int firstColon = rest.indexOf(':');
            final String sanField = (firstColon >= 0) ? rest.substring(0, firstColon) : rest;
            final String glob = (firstColon >= 0) ? rest.substring(firstColon + 1) : null;

            final SANType sanType;
            try {
                sanType = parseSanTypeToken(sanField);
            } catch (IllegalArgumentException e) {
                log.warn("Unsupported SAN type '{}' in attribute '{}'", sanField, raw);
                return null;
            }

            WildcardMatcher matcher = null; // null means pass-through
            if (!Strings.isNullOrEmpty(glob)) {
                // we only support '*' for now
                if (glob.indexOf('?') >= 0 || (glob.startsWith("/") && glob.endsWith("/"))) {
                    log.warn("Unsupported SAN glob (only '*' allowed, case-insensitive). attribute='{}'", raw);
                    return null;
                }
                matcher = WildcardMatcher.from(glob).ignoreCase();
            }
            return ParsedAttribute.san(new ParsedSAN(sanType.getValue(), matcher));
        }

        // DN form: either "dn:cn" or just "cn"
        final String dnAttr = s.regionMatches(true, 0, "dn:", 0, 3) ? s.substring(3) : s;
        return ParsedAttribute.dn(dnAttr);
    }

    public HTTPClientCertAuthenticator(final Settings settings, final Path configPath) {
        this.settings = settings;
        this.skipUsersMatcher = WildcardMatcher.from(settings.getAsList(OPENDISTRO_SECURITY_SSL_SKIP_USERS));
        this.parsedUsernameAttr = parseAttributeSetting(settings.get("username_attribute"));
        this.parsedRolesAttr = parseAttributeSetting(settings.get("roles_attribute"));
    }

    @Override
    public AuthCredentials extractCredentials(final SecurityRequest request, final ThreadContext threadContext) {
        final String principal = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL);
        if (Strings.isNullOrEmpty(principal)) {
            log.trace("No CLIENT CERT, send 401");
            return null;
        }
        if (skipUsersMatcher.test(principal)) {
            log.debug("Skipped user client cert authentication of user {} as its in skip_users list ", principal);
            return null;
        }

        try {
            final String username = extractUsername(threadContext, principal);
            final String[] roles = extractRoles(threadContext, principal);
            return new AuthCredentials(username, roles).markComplete();
        } catch (InvalidNameException e) {
            if (log.isDebugEnabled()) {
                log.warn("Invalid client certificate DN; principal='{}'", principal, e);
            } else {
                log.warn("Client cert had no properly formed DN.  {}", e.getMessage());
            }

            return null;
        }
    }

    private String extractUsername(ThreadContext ctx, String principal) throws InvalidNameException {
        // Default: full DN
        if (parsedUsernameAttr == null || (parsedUsernameAttr.type == AttributeType.DN && parsedUsernameAttr.dnAttr == null)) {
            return principal;
        }

        List<String> usernames;
        if (parsedUsernameAttr.type == AttributeType.DN) {
            usernames = getDnAttribute(new LdapName(principal), parsedUsernameAttr.dnAttr);
        } else {
            usernames = extractFromSAN(ctx, parsedUsernameAttr.san);
        }
        // Username rule: pick the FIRST match; else fallback to full DN
        return (usernames == null || usernames.isEmpty()) ? principal : usernames.get(0);
    }

    private String[] extractRoles(ThreadContext ctx, String principal) throws InvalidNameException {
        if (parsedRolesAttr == null || (parsedRolesAttr.type == AttributeType.DN && parsedRolesAttr.dnAttr == null)) {
            return null;
        }
        List<String> roles;
        if (parsedRolesAttr.type == AttributeType.DN) {
            roles = getDnAttribute(new LdapName(principal), parsedRolesAttr.dnAttr);
        } else {
            roles = extractFromSAN(ctx, parsedRolesAttr.san);
        }
        return roles == null || roles.isEmpty() ? null : roles.toArray(new String[0]);
    }

    private List<String> getDnAttribute(LdapName rfc2253dn, String attribute) {
        final List<String> attrValues = new ArrayList<>(rfc2253dn.size());
        final List<Rdn> reverseRdn = new ArrayList<>(rfc2253dn.getRdns());
        Collections.reverse(reverseRdn);

        for (Rdn rdn : reverseRdn) {
            if (rdn.getType().equalsIgnoreCase(attribute)) {
                attrValues.add(rdn.getValue().toString());
            }
        }

        return Collections.unmodifiableList(attrValues);
    }

    private static final int MAX_SAN_MATCHES = 16;
    private static final int MAX_SAN_VALUE_LEN = 8192;

    private List<String> extractFromSAN(ThreadContext ctx, ParsedSAN psan) {
        if (psan == null) return Collections.emptyList();

        final X509Certificate[] peerCertificates = ctx.getTransient(ConfigConstants.OPENDISTRO_SECURITY_SSL_PEER_CERTIFICATES);
        if (peerCertificates == null || peerCertificates.length == 0) {
            return Collections.emptyList();
        }

        try {
            final Collection<List<?>> altNames = peerCertificates[0].getSubjectAlternativeNames();
            if (altNames == null) return Collections.emptyList();

            return altNames.stream()
                .filter(entry -> entry != null && entry.size() >= 2)
                .filter(entry -> entry.get(0) instanceof Integer i && i.intValue() == psan.type())
                .map(entry -> sanValueToString(psan.type(), entry.get(1)))
                .map(v -> {
                    if (Strings.isNullOrEmpty(v)) return null;
                    // Bound input length for safety before glob
                    final String s = v.length() > MAX_SAN_VALUE_LEN ? v.substring(0, MAX_SAN_VALUE_LEN) : v;
                    if (psan.matcher() == null) return s; // no filter -> pass-through
                    return psan.matcher().test(s) ? s : null;
                })
                .filter(Objects::nonNull)
                .limit(MAX_SAN_MATCHES)
                .collect(Collectors.toList());
        } catch (CertificateParsingException e) {
            log.error("Error parsing X509 certificate", e);
            return Collections.emptyList();
        }
    }

    // sometimes IP address is of type of byte[]
    private static String sanValueToString(int type, Object value) {
        if (value == null) return null;
        if (value instanceof String) return (String) value;
        if (type == SANType.IP_ADDRESS.value && value instanceof byte[]) {
            byte[] addr = (byte[]) value;
            try {
                return java.net.InetAddress.getByAddress(addr).getHostAddress();
            } catch (java.net.UnknownHostException e) {
                return null;
            }
        }
        return null;
    }

    @Override
    public Optional<SecurityResponse> reRequestAuthentication(final SecurityRequest response, AuthCredentials creds) {
        return Optional.empty();
    }

    @Override
    public String getType() {
        return "clientcert";
    }

    private static SANType parseSanTypeToken(String token) {
        final String t = token.toLowerCase(Locale.ROOT);
        return switch (t) {
            case "othername" -> SANType.OTHER_NAME;
            case "rfc822name" -> SANType.EMAIL;
            case "dnsname" -> SANType.DNS; // RFC prints dNSName
            case "x400address" -> SANType.X400_ADDRESS;
            case "directoryname" -> SANType.DIRECTORY_NAME;
            case "edipartyname" -> SANType.EDI_PARTY_NAME;
            case "uniformresourceidentifier" -> SANType.URI;
            case "ipaddress" -> SANType.IP_ADDRESS;    // RFC prints iPAddress
            case "registeredid" -> SANType.REGISTERED_ID;
            default -> throw new IllegalArgumentException("Unsupported SAN type token: " + token);
        };
    }

    /**
     * Enumeration of supported SAN (Subject Alternative Name) types as defined in RFC 5280.
     * https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
     */
    private enum SANType {
        OTHER_NAME(0), // OtherName
        EMAIL(1), // rfc822Name
        DNS(2), // dNSName
        X400_ADDRESS(3), // x400Address
        DIRECTORY_NAME(4), // directoryName
        EDI_PARTY_NAME(5), // ediPartyName
        URI(6), // uniformResourceIdentifier
        IP_ADDRESS(7), // iPAddress
        REGISTERED_ID(8); // registeredID

        private static final Map<Integer, SANType> lookup = EnumSet.allOf(SANType.class)
            .stream()
            .collect(Collectors.toMap(SANType::getValue, sanType -> sanType));

        private final int value;

        SANType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static SANType fromValue(int value) {
            return lookup.get(value);
        }
    }
}
