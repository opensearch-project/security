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

package org.opensearch.security.hasher;

import org.junit.Ignore;

/**
 * FIPS variant of {@link BCryptPasswordHasherTests}: BCrypt is not FIPS-compliant, so
 * the whole suite is out of scope under FIPS.
 */
@Ignore("BCrypt is not FIPS-compliant")
public class BCryptPasswordHasherFipsTests extends BCryptPasswordHasherTests {}
