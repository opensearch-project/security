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

package org.opensearch.security.tools.democonfig;

/**
 * Default ExitHandler implementation that calls System.exit.
 */
public final class DefaultExitHandler implements ExitHandler {
    @Override
    public void exit(int status) {
        System.exit(status);
    }
}
