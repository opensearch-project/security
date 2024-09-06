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
package org.opensearch.security.identity;

import java.util.Objects;
import java.util.concurrent.Callable;

import org.opensearch.identity.PluginSubject;

public class PluginContextSwitcher {
    private PluginSubject pluginSubject;

    public PluginContextSwitcher() {}

    public void initialize(PluginSubject pluginSubject) {
        this.pluginSubject = pluginSubject;
    }

    public <T> T runAs(Callable<T> callable) {
        Objects.requireNonNull(pluginSubject);
        try {
            return pluginSubject.runAs(callable);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
