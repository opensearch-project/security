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

package org.opensearch.sample;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.SpecialPermission;
import org.opensearch.security.spi.resources.ResourceParser;

@SuppressWarnings("removal")
public class SampleResourceParser implements ResourceParser<SampleResource> {
    @Override
    public SampleResource parse(String s) throws IOException {
        ObjectMapper obj = new ObjectMapper();
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            return AccessController.doPrivileged((PrivilegedExceptionAction<SampleResource>) () -> obj.readValue(s, SampleResource.class));
        } catch (final PrivilegedActionException e) {
            throw (IOException) e.getCause();
        }
    }
}
