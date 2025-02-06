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
package org.opensearch.security.support;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auth.blocking.ClientBlockRegistry;
import org.opensearch.security.auth.limiting.AddressBasedRateLimiter;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.support.SecurityUtils.ENVBASE64_PATTERN;
import static org.opensearch.security.support.SecurityUtils.ENVBC_PATTERN;
import static org.opensearch.security.support.SecurityUtils.ENV_PATTERN;

public class SecurityUtilsTest {

    private final Collection<String> interestingEnvKeyNames = List.of(
        "=ExitCode",
        "=C:",
        "ProgramFiles(x86)",
        "INPUT_GRADLE-HOME-CACHE-CLEANUP",
        "MYENV",
        "MYENV:",
        "MYENV::"
    );
    private final Collection<String> namesFromThisRuntimeEnvironment = System.getenv().keySet();

    @Test
    public void checkInterestingNamesForEnvPattern() {
        checkKeysWithPredicate(interestingEnvKeyNames, "env", ENV_PATTERN.asMatchPredicate());
    }

    @Test
    public void checkRuntimeKeyNamesForEnvPattern() {
        checkKeysWithPredicate(namesFromThisRuntimeEnvironment, "env", ENV_PATTERN.asMatchPredicate());
    }

    @Test
    public void checkInterestingNamesForEnvbcPattern() {
        checkKeysWithPredicate(interestingEnvKeyNames, "envbc", ENVBC_PATTERN.asMatchPredicate());
    }

    @Test
    public void checkInterestingNamesForEnvBase64Pattern() {
        checkKeysWithPredicate(interestingEnvKeyNames, "envbase64", ENVBASE64_PATTERN.asMatchPredicate());
    }

    private void checkKeysWithPredicate(Collection<String> keys, String predicateName, Predicate<String> predicate) {
        keys.forEach(envKeyName -> {
            final String prefixWithKeyName = "${" + predicateName + "." + envKeyName;

            final String baseKeyName = prefixWithKeyName + "}";
            assertThat("Testing " + envKeyName + ", " + baseKeyName, predicate.test(baseKeyName), equalTo(true));

            final String baseKeyNameWithDefault = prefixWithKeyName + ":-tTt}";
            assertThat(
                "Testing " + envKeyName + " with defaultValue, " + baseKeyNameWithDefault,
                predicate.test(baseKeyNameWithDefault),
                equalTo(true)
            );
        });
    }

    @Test
    public void testHostMatching() throws UnknownHostException {
        assertThat(SecurityUtils.matchesHostPatterns(null, null, "ip-only"), is(false));
        assertThat(SecurityUtils.matchesHostPatterns(null, null, null), is(false));
        assertThat(SecurityUtils.matchesHostPatterns(WildcardMatcher.from(List.of("127.0.0.1")), null, "ip-only"), is(false));
        assertThat(SecurityUtils.matchesHostPatterns(null, InetAddress.getByName("127.0.0.1"), "ip-only"), is(false));
        assertThat(
            SecurityUtils.matchesHostPatterns(WildcardMatcher.from(List.of("127.0.0.1")), InetAddress.getByName("127.0.0.1"), "ip-only"),
            is(true)
        );
        assertThat(
            SecurityUtils.matchesHostPatterns(WildcardMatcher.from(List.of("127.0.0.*")), InetAddress.getByName("127.0.0.1"), "ip-only"),
            is(true)
        );
        assertThat(
            SecurityUtils.matchesHostPatterns(
                WildcardMatcher.from(List.of("127.0.0.1")),
                InetAddress.getByName("localhost"),
                "ip-hostname"
            ),
            is(true)
        );
        assertThat(
            SecurityUtils.matchesHostPatterns(WildcardMatcher.from(List.of("127.0.0.1")), InetAddress.getByName("localhost"), "ip-only"),
            is(true)
        );
        assertThat(
            SecurityUtils.matchesHostPatterns(
                WildcardMatcher.from(List.of("127.0.0.1")),
                InetAddress.getByName("localhost"),
                "ip-hostname"
            ),
            is(true)
        );
        assertThat(
            SecurityUtils.matchesHostPatterns(
                WildcardMatcher.from(List.of("127.0.0.1")),
                InetAddress.getByName("example.org"),
                "ip-hostname"
            ),
            is(false)
        );
        assertThat(
            SecurityUtils.matchesHostPatterns(
                WildcardMatcher.from(List.of("example.org")),
                InetAddress.getByName("example.org"),
                "ip-hostname"
            ),
            is(true)
        );
        assertThat(
            SecurityUtils.matchesHostPatterns(
                WildcardMatcher.from(List.of("example.org")),
                InetAddress.getByName("example.org"),
                "ip-only"
            ),
            is(false)
        );
        assertThat(
            SecurityUtils.matchesHostPatterns(
                WildcardMatcher.from(List.of("*example.org")),
                InetAddress.getByName("example.org"),
                "ip-hostname"
            ),
            is(true)
        );
        assertThat(
            SecurityUtils.matchesHostPatterns(
                WildcardMatcher.from(List.of("example.*")),
                InetAddress.getByName("example.org"),
                "ip-hostname"
            ),
            is(true)
        );
        assertThat(
            SecurityUtils.matchesHostPatterns(
                WildcardMatcher.from(List.of("opensearch.org")),
                InetAddress.getByName("example.org"),
                "ip-hostname"
            ),
            is(false)
        );
    }

    @Test
    public void testMatchesCidrPatternNullValues() throws UnknownHostException {
        Settings settings = Settings.builder().put("ignore_hosts", "192.168.1.0/24").build();
        InetAddress address = InetAddress.getByName("192.168.1.1");
        ClientBlockRegistry<InetAddress> clientBlockRegistry = new AddressBasedRateLimiter(settings, null);

        assertThat(SecurityUtils.matchesCidrPatterns(null, address), is(false));
        assertThat(SecurityUtils.matchesCidrPatterns(clientBlockRegistry, null), is(false));
    }

    @Test
    public void testMatchesCidrPatternIpOnly() throws UnknownHostException {
        Settings settings = Settings.builder().put("ignore_hosts", "192.168.1.0").build();
        InetAddress address = InetAddress.getByName("192.168.1.1");
        ClientBlockRegistry<InetAddress> clientBlockRegistry = new AddressBasedRateLimiter(settings, null);

        assertThat(SecurityUtils.matchesCidrPatterns(clientBlockRegistry, address), is(false));
    }

    @Test
    public void testMatchesCidrPatternHostOnly() throws UnknownHostException {
        Settings settings = Settings.builder().put("ignore_hosts", "example.com").build();
        InetAddress address = InetAddress.getByName("192.168.1.1");
        ClientBlockRegistry<InetAddress> clientBlockRegistry = new AddressBasedRateLimiter(settings, null);

        assertThat(SecurityUtils.matchesCidrPatterns(clientBlockRegistry, address), is(false));
    }

    @Test
    public void testMatchesCidrPatternSingleValidCidrMatch() throws UnknownHostException {
        Settings settings = Settings.builder().put("ignore_hosts", "192.168.1.0/24").build();
        InetAddress address = InetAddress.getByName("192.168.1.1");
        ClientBlockRegistry<InetAddress> clientBlockRegistry = new AddressBasedRateLimiter(settings, null);
        assertThat(SecurityUtils.matchesCidrPatterns(clientBlockRegistry, address), is(true));
    }

    @Test
    public void testMatchesCidrPatternSingleValidCidrNoMatch() throws UnknownHostException {
        Settings settings = Settings.builder().put("ignore_hosts", "192.168.1.0/24").build();
        InetAddress address = InetAddress.getByName("10.0.0.1");
        ClientBlockRegistry<InetAddress> clientBlockRegistry = new AddressBasedRateLimiter(settings, null);
        assertThat(SecurityUtils.matchesCidrPatterns(clientBlockRegistry, address), is(false));
    }

    @Test
    public void testMatchesCidrPatternMultipleValidCidrsMatch() throws UnknownHostException {
        Settings settings = Settings.builder().put("ignore_hosts", "192.168.1.0/24,10.0.0.0/8").build();
        InetAddress address = InetAddress.getByName("192.168.1.1");
        ClientBlockRegistry<InetAddress> clientBlockRegistry = new AddressBasedRateLimiter(settings, null);
        assertThat(SecurityUtils.matchesCidrPatterns(clientBlockRegistry, address), is(true));
    }

    @Test
    public void testMatchesCidrPatternInvalidCidrWithValidAddressAndInvalidCidrLast() throws UnknownHostException {
        Settings settings = Settings.builder().put("ignore_hosts", "192.168.1.0/24, invalid/cidr").build();
        InetAddress address = InetAddress.getByName("192.168.1.1");
        ClientBlockRegistry<InetAddress> clientBlockRegistry = new AddressBasedRateLimiter(settings, null);
        assertThat(SecurityUtils.matchesCidrPatterns(clientBlockRegistry, address), is(true));
    }

    @Test
    public void testMatchesCidrPatternInvalidCidrWithValidAddressAndInvalidCidrFirst() throws UnknownHostException {
        Settings settings = Settings.builder().put("ignore_hosts", "invalid/cidr, 192.168.1.0/24").build();
        InetAddress address = InetAddress.getByName("192.168.1.1");
        ClientBlockRegistry<InetAddress> clientBlockRegistry = new AddressBasedRateLimiter(settings, null);
        assertThat(SecurityUtils.matchesCidrPatterns(clientBlockRegistry, address), is(true));
    }
}
