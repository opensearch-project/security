/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.util;

import com.carrotsearch.randomizedtesting.ThreadFilter;

/**
 * Thread-leak filter for the "BC FIPS Entropy Daemon", which the framework's {@code BouncyCastleThreadFilter}
 * does not yet cover. Shared by tests that touch BC FIPS keystores/crypto under {@code RandomizedRunner}.
 */
public class BCFipsEntropyDaemonFilter implements ThreadFilter {
    @Override
    public boolean reject(Thread t) {
        return "BC FIPS Entropy Daemon".equals(t.getName());
    }
}
