/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.matcher;

import org.hamcrest.Matcher;

import static java.util.Objects.requireNonNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;

public class ExceptionMatcherAssert {

    @FunctionalInterface
    public interface ThrowingCallable {
        void call() throws Exception;
    }

    public static void assertThatThrownBy(ThrowingCallable throwingCallable, Matcher<? super Throwable> matcher) {
        Throwable expectedException = catchThrowable(throwingCallable);
        assertThat("Expected exception was not thrown", expectedException, notNullValue());
        assertThat(expectedException, matcher);
    }

    public static Throwable catchThrowable(ThrowingCallable throwingCallable) {
        Throwable expectedException = null;
        try {
            requireNonNull(throwingCallable, "ThrowingCallable must not be null.").call();
        } catch (Throwable e) {
            expectedException = e;
        }
        return expectedException;
    }
}
