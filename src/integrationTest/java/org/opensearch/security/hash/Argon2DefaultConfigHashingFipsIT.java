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

package org.opensearch.security.hash;

import org.junit.Ignore;

/**
 * FIPS variant of {@link Argon2DefaultConfigHashingTests}: Argon2 is (yet) not FIPS-compliant,
 * so the whole suite is out of scope under FIPS.
 */
@Ignore("Argon2 is not FIPS-compliant")
public class Argon2DefaultConfigHashingFipsIT extends Argon2DefaultConfigHashingTests {}
