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

package org.opensearch.security.privileges.dlsfls;

import org.opensearch.security.configuration.Salt;

public class FieldMaskingTestHelper {

    public static final FieldMasking.Config CONFIG_DEFAULT = new FieldMasking.Config(null, new Salt(new byte[Salt.SALT_SIZE]));
}
