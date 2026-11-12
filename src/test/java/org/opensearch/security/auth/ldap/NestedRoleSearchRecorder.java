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

package org.opensearch.security.auth.ldap;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.message.Message;

/**
 * Records the group DN of each role search that an LDAP authorization backend makes while it resolves nested roles,
 * read from the trace message the backend logs once for each search.
 */
public final class NestedRoleSearchRecorder extends AbstractAppender implements AutoCloseable {

    private static final String GROUP_BASE_SUFFIX = ",ou=groups,o=TEST";

    private final Logger logger;
    private final Level previousLevel;
    private final List<String> searchedGroups = new CopyOnWriteArrayList<>();

    private NestedRoleSearchRecorder(final Class<?> backendClass) {
        super("NestedRoleSearchRecorder", null, null, true, Property.EMPTY_ARRAY);
        this.logger = (Logger) LogManager.getLogger(backendClass);
        this.previousLevel = logger.getLevel();
        start();
        logger.addAppender(this);
        logger.setLevel(Level.TRACE);
    }

    /**
     * Starts recording the role searches of a backend.
     *
     * @param backendClass the backend whose logger is read
     * @return the recorder, to be closed when the code under test is done
     */
    public static NestedRoleSearchRecorder record(final Class<?> backendClass) {
        return new NestedRoleSearchRecorder(backendClass);
    }

    /**
     * Returns the searched group DNs, once for each search.
     *
     * @return the DNs below {@code ou=groups,o=TEST} that a role search was made for
     */
    public List<String> searchedGroups() {
        return List.copyOf(searchedGroups);
    }

    @Override
    public void append(final LogEvent event) {
        final Message message = event.getMessage();
        final Object[] parameters = message.getParameters();
        if (message.getFormat() != null
            && message.getFormat().startsWith("Results for LDAP group search for ")
            && parameters != null
            && parameters.length > 0
            && String.valueOf(parameters[0]).endsWith(GROUP_BASE_SUFFIX)) {
            searchedGroups.add(String.valueOf(parameters[0]));
        }
    }

    @Override
    public void close() {
        logger.removeAppender(this);
        logger.setLevel(previousLevel);
        stop();
    }
}
