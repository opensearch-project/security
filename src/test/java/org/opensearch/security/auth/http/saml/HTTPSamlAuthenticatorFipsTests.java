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

package org.opensearch.security.auth.http.saml;

import org.junit.Ignore;

/**
 * FIPS variant of {@link HTTPSamlAuthenticatorTest}. The SAML frameworks the authenticator
 * builds on are not FIPS-compliant, so the whole suite is out of scope under FIPS; this class
 * exists so the baseline is replaced rather than silently dropped.
 */
@Ignore("SAML frameworks are not FIPS-compliant")
public class HTTPSamlAuthenticatorFipsTests extends HTTPSamlAuthenticatorTest {}
