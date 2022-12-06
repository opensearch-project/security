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

import java.util.Arrays;
import java.util.Collection;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.SecurityUtils.ENVBASE64_PATTERN;
import static org.opensearch.security.support.SecurityUtils.ENVBC_PATTERN;
import static org.opensearch.security.support.SecurityUtils.ENV_PATTERN;

public class SecurityUtilsTest {

    private final Collection<String> interestingEnvKeyNames = Arrays.asList(
        "=ExitCode",
        "=C:",
        "ProgramFiles(x86)",
        "INPUT_GRADLE-HOME-CACHE-CLEANUP",
        "MYENV",
        "MYENV:",
        "MYENV::",
        "JAVA_HOME_14.0.2_x64"
    );
    private final Collection<String> namesFromThisRuntimeEnvironment = System.getenv().keySet();

    @Test
    public void checkInterestingNamesForEnvPattern() {
        checkKeysWithPredicate(interestingEnvKeyNames, "env", asMatchPredicate(ENV_PATTERN));
    }

    @Test
    public void checkRuntimeKeyNamesForEnvPattern() {
        checkKeysWithPredicate(namesFromThisRuntimeEnvironment, "env", asMatchPredicate(ENV_PATTERN));
    }

    @Test
    public void checkInterestingNamesForEnvbcPattern() {
        checkKeysWithPredicate(interestingEnvKeyNames, "envbc", asMatchPredicate(ENVBC_PATTERN));
    }

    @Test
    public void checkInterestingNamesForEnvBase64Pattern() {
        checkKeysWithPredicate(interestingEnvKeyNames, "envbase64", asMatchPredicate(ENVBASE64_PATTERN));
    }

    private Predicate<String> asMatchPredicate(final Pattern p) {
        return (String s) -> p.matcher(s).matches();
    }

    private void checkKeysWithPredicate(Collection<String> keys, String predicateName, Predicate<String> predicate) {
        keys.forEach(envKeyName -> {
            final String prefixWithKeyName = "${" + predicateName + "." + envKeyName;

            final String baseKeyName = prefixWithKeyName + "}";
            assertThat("Testing " + envKeyName + ", " + baseKeyName,
                predicate.test(baseKeyName),
                equalTo(true));

            final String baseKeyNameWithDefault = prefixWithKeyName + ":-tTt}";
            assertThat("Testing " + envKeyName + " with defaultValue, " + baseKeyNameWithDefault,
                predicate.test(baseKeyNameWithDefault),
                equalTo(true));
        });
    }
}
