/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.matcher.client;

import org.hamcrest.Matcher;

import org.opensearch.core.rest.RestStatus;

public class TransportExceptionMatchers {

    private TransportExceptionMatchers() {}

    public static Matcher<Throwable> statusException(RestStatus expectedRestStatus) {
        return new TransportExceptionMatcher(expectedRestStatus);
    }
}
