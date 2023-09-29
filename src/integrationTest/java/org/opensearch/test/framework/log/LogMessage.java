/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.log;

import java.util.Objects;
import java.util.Optional;

import org.apache.commons.lang3.exception.ExceptionUtils;

class LogMessage {

    private final String message;
    private final String stackTrace;

    public LogMessage(String message, Throwable throwable) {
        this.message = message;
        this.stackTrace = Optional.ofNullable(throwable).map(ExceptionUtils::getStackTrace).orElse("");
    }

    public boolean containMessage(String expectedMessage) {
        Objects.requireNonNull(expectedMessage, "Expected message must not be null.");
        return expectedMessage.equals(message);
    }

    public boolean stackTraceContains(String stackTraceFragment) {
        Objects.requireNonNull(stackTraceFragment, "Stack trace fragment is required.");
        return stackTrace.contains(stackTraceFragment);
    }

    public String getMessage() {
        return message;
    }
}
