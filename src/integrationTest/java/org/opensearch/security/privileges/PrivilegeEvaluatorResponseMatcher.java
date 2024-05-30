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
package org.opensearch.security.privileges;

import java.util.Arrays;
import java.util.Set;

import com.google.common.collect.ImmutableSet;
import org.hamcrest.Description;
import org.hamcrest.DiagnosingMatcher;

/**
 * Provides hamcrest matchers for PrivilegesEvaluatorResponse instances, which can be used with assertThat() calls.
 */
public abstract class PrivilegeEvaluatorResponseMatcher extends DiagnosingMatcher<PrivilegesEvaluatorResponse> {

    /**
     * Asserts that the status of the PrivilegesEvaluatorResponse is "allowed".
     */
    public static PrivilegeEvaluatorResponseMatcher isAllowed() {
        return new PrivilegeEvaluatorResponseMatcher() {
            @Override
            public void describeTo(Description description) {
                description.appendText("Request is fully allowed; isAllowed() returns true");
            }

            @Override
            protected boolean matches(PrivilegesEvaluatorResponse response, Description mismatchDescription) {
                if (!response.isAllowed()) {
                    mismatchDescription.appendText("isAllowed() is false");
                    return false;
                }

                if (response.isPartiallyOk()) {
                    mismatchDescription.appendText("isPartiallyOk() must be false if isAllowed() is true");
                    return false;
                }

                if (!response.getMissingPrivileges().isEmpty()) {
                    mismatchDescription.appendText("getMissingPrivileges() must be empty if isAllowed() is true");
                    return false;
                }

                return true;
            }
        };
    }

    /**
     * Asserts that the status of the PrivilegesEvaluatorResponse is neither "allowed" or "partially allowed". You can
     * add missingPrivileges sub-matchers to verify the actually missing privileges.
     */
    public static PrivilegeEvaluatorResponseMatcher isForbidden(PrivilegeEvaluatorResponseMatcher... subMatchers) {
        return new PrivilegeEvaluatorResponseMatcher() {
            @Override
            public void describeTo(Description description) {
                description.appendText("Request is fully forbidden; isAllowed() returns false; isPartiallyOk() returns false");

                for (PrivilegeEvaluatorResponseMatcher subMatcher : subMatchers) {
                    description.appendText("; ");
                    subMatcher.describeTo(description);
                }
            }

            @Override
            protected boolean matches(PrivilegesEvaluatorResponse response, Description mismatchDescription) {
                if (response.isAllowed()) {
                    mismatchDescription.appendText("isAllowed() is true");
                    return false;
                }

                if (response.isPartiallyOk()) {
                    mismatchDescription.appendText("isPartiallyOk() is true");
                    return false;
                }

                for (PrivilegeEvaluatorResponseMatcher subMatcher : subMatchers) {
                    if (!subMatcher.matches(response, mismatchDescription)) {
                        return false;
                    }
                }

                return true;
            }
        };
    }

    /**
     * Asserts that the status of the PrivilegesEvaluatorResponse is "partially ok". You can specify the available
     * indices are parameter.
     */
    public static PrivilegeEvaluatorResponseMatcher isPartiallyOk(String... availableIndices) {
        return new PrivilegeEvaluatorResponseMatcher() {
            @Override
            public void describeTo(Description description) {
                description.appendText(
                    "Request is allowed for a subset of indices; isPartiallyOk() returns true; getAvailableIndices() returns "
                ).appendValue(Arrays.asList(availableIndices));
            }

            @Override
            protected boolean matches(PrivilegesEvaluatorResponse response, Description mismatchDescription) {
                if (!response.isPartiallyOk()) {
                    mismatchDescription.appendText("isPartiallyOk() is false");
                    return false;
                }

                if (response.isAllowed()) {
                    mismatchDescription.appendText("isAllowed() must be false if isPartiallyOk() is true");
                    return false;
                }

                if (!response.getAvailableIndices().equals(ImmutableSet.copyOf(availableIndices))) {
                    mismatchDescription.appendText("getAvailableIndices() is ").appendValue(Arrays.asList(response.getAvailableIndices()));
                    return false;
                }

                return true;
            }
        };
    }

    /**
     * Asserts that the missingPrivileges property of a PrivilegesEvaluatorResponse instance equals to the given parameters.
     * Should be used as a sub-matcher for isForbidden().
     */
    public static PrivilegeEvaluatorResponseMatcher missingPrivileges(String... missingPrivileges) {
        return missingPrivileges(ImmutableSet.copyOf(missingPrivileges));
    }

    /**
     * Asserts that the missingPrivileges property of a PrivilegesEvaluatorResponse instance equals to the given parameters.
     * Should be used as a sub-matcher for isForbidden().
     */
    public static PrivilegeEvaluatorResponseMatcher missingPrivileges(Set<String> missingPrivileges) {
        return new PrivilegeEvaluatorResponseMatcher() {
            @Override
            public void describeTo(Description description) {
                description.appendText("Missing privileges are ");
                description.appendValue(missingPrivileges);
            }

            @Override
            protected boolean matches(PrivilegesEvaluatorResponse response, Description mismatchDescription) {
                if (!response.getMissingPrivileges().equals(missingPrivileges)) {
                    mismatchDescription.appendText("getMissingPrivileges() returns ").appendValue(response.getMissingPrivileges());
                    return false;
                }

                return true;
            }
        };
    }

    @Override
    protected boolean matches(Object o, Description mismatchDescription) {
        if (!(o instanceof PrivilegesEvaluatorResponse)) {
            mismatchDescription.appendText("The object is not an instance of PrivilegesEvaluatorResponse: ").appendValue(o);
        }

        PrivilegesEvaluatorResponse response = (PrivilegesEvaluatorResponse) o;

        if (matches(response, mismatchDescription)) {
            return true;
        } else {
            mismatchDescription.appendText("\n");
            mismatchDescription.appendText(response.toString());
            return false;
        }
    }

    protected abstract boolean matches(PrivilegesEvaluatorResponse response, Description mismatchDescription);

}
