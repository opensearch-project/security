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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.collections.Buffer;
import org.apache.commons.collections.BufferUtils;
import org.apache.commons.collections.buffer.CircularFifoBuffer;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Core;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;

import static org.opensearch.test.framework.log.LogCapturingAppender.PLUGIN_NAME;

@Plugin(name = PLUGIN_NAME, category = Core.CATEGORY_NAME, elementType = Appender.ELEMENT_TYPE, printObject = true)
public class LogCapturingAppender extends AbstractAppender {

	public final static String PLUGIN_NAME = "LogCapturingAppender";
	public static final int MAX_SIZE = 100;
	private static final Buffer messages = BufferUtils.synchronizedBuffer(new CircularFifoBuffer(MAX_SIZE));

	private static final Set<String> activeLoggers = Collections.synchronizedSet(new HashSet<>());

	protected LogCapturingAppender(String name, Filter filter, Layout<? extends Serializable> layout, boolean ignoreExceptions, Property[] properties) {
		super(name, filter, layout, ignoreExceptions, properties);
	}

	@PluginFactory
	public static LogCapturingAppender createAppender(@PluginAttribute(value = "name", defaultString = "logCapturingAppender") String name) {
		return new LogCapturingAppender(name,  null, null, true, Property.EMPTY_ARRAY);
	}

	@Override
	public void append(LogEvent event) {
		String loggerName = event.getLoggerName();
		boolean loggable = activeLoggers.contains(loggerName);
		if(loggable) {
			messages.add(event.getMessage().getFormattedMessage());
		}
	}

	public static void enable(String...loggerNames) {
		disable();
		activeLoggers.addAll(Arrays.asList(loggerNames));
	}

	public static void disable() {
		activeLoggers.clear();
		messages.clear();
	}

	public static List<String> getLogMessages() {
		return new ArrayList<>(messages);
	}

	@Override
	public String toString() {
		return "LogCapturingAppender{}";
	}
}
