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

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.junit.rules.ExternalResource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;

public class LogsRule extends ExternalResource {

	private final String[] loggerNames;

	public LogsRule(String...loggerNames) {
		this.loggerNames = Objects.requireNonNull(loggerNames, "Logger names are required");
	}

	@Override
	protected void before() {
		LogCapturingAppender.enable(loggerNames);
	}

	@Override
	protected void after() {
		LogCapturingAppender.disable();
	}

	public void assertThatContain(String expectedLogMessage) {
		List<String> messages = LogCapturingAppender.getLogMessages();
		String reason = reasonMessage(expectedLogMessage, messages);
		assertThat(reason, messages, hasItem(expectedLogMessage));
	}

	private static String reasonMessage(String expectedLogMessage, List<String> messages) {
		String concatenatedLogMessages = messages.stream()
			.map(message -> String.format("'%s'", message))
			.collect(Collectors.joining(", "));
		return String.format("Expected message '%s' has not been found in logs. All captured log messages: %s",
			expectedLogMessage,
			concatenatedLogMessages);
	}
}
