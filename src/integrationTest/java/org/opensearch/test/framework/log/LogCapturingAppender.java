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
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import com.google.common.collect.EvictingQueue;
import com.google.common.collect.Queues;
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

/**
* <p>The class acts as Log4j2 appender with a special purpose. The appender is used to capture logs which are generated during tests and
* then test can examine logs. To use the appender it is necessary to:</p>
* <ol>
*     <li>Add package with appender to log4j2 package scan in Log4j2 configuration file</li>
*     <li>Create appender in log4j2 configuration</li>
*     <li>Assign required loggers to appender</li>
*     <li>Enable appender for certain classes with method {@link #enable(String...)}. Each test can enable appender for distinct classes</li>
* </ol>
*/
@Plugin(name = PLUGIN_NAME, category = Core.CATEGORY_NAME, elementType = Appender.ELEMENT_TYPE, printObject = true)
public class LogCapturingAppender extends AbstractAppender {

    public final static String PLUGIN_NAME = "LogCapturingAppender";
    /**
    * Appender stores only last <code>MAX_SIZE</code> messages to avoid excessive RAM memory usage.
    */
    public static final int MAX_SIZE = 100;

    /**
    * Buffer for captured log messages
    */
    private static final Queue<LogMessage> messages = Queues.synchronizedQueue(EvictingQueue.create(MAX_SIZE));

    /**
    * Log messages are stored in buffer {@link #messages} only for classes which are added to the {@link #activeLoggers} set.
    */
    private static final Set<String> activeLoggers = ConcurrentHashMap.newKeySet();

    protected LogCapturingAppender(
        String name,
        Filter filter,
        Layout<? extends Serializable> layout,
        boolean ignoreExceptions,
        Property[] properties
    ) {
        super(name, filter, layout, ignoreExceptions, properties);
    }

    /**
    * Method used by Log4j2 to create appender
    * @param name appender name from Log4j2 configuration
    * @return newly created appender
    */
    @PluginFactory
    public static LogCapturingAppender createAppender(
        @PluginAttribute(value = "name", defaultString = "logCapturingAppender") String name
    ) {
        return new LogCapturingAppender(name, null, null, true, Property.EMPTY_ARRAY);
    }

    /**
    * Method invoked by Log4j2 to append log events
    * @param event The LogEvent, represents log message.
    */
    @Override
    public void append(LogEvent event) {
        String loggerName = event.getLoggerName();
        boolean loggable = activeLoggers.contains(loggerName);
        if (loggable) {
            event.getThrown();
            messages.add(new LogMessage(event.getMessage().getFormattedMessage(), event.getThrown()));
        }
    }

    /**
    * To collect log messages form given logger the logger name must be passed to {@link #enable(String...)} method.
    * @param loggerNames logger names
    */
    public static void enable(String... loggerNames) {
        disable();
        activeLoggers.addAll(Arrays.asList(loggerNames));
    }

    /**
    * Invocation cause that appender stops collecting log messages. Additionally, memory used by collected messages so far is released.
    */
    public static void disable() {
        activeLoggers.clear();
        messages.clear();
    }

    /**
    * Is used to obtain gathered log messages
    * @return Log messages
    */
    public static List<LogMessage> getLogMessages() {
        return new ArrayList<>(messages);
    }

    public static List<String> getLogMessagesAsString() {
        return getLogMessages().stream().map(LogMessage::getMessage).collect(Collectors.toList());
    }

    @Override
    public String toString() {
        return "LogCapturingAppender{}";
    }
}
