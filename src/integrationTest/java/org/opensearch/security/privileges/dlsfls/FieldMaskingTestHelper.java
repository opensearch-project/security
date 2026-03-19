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

import org.opensearch.common.settings.Settings;

public class FieldMaskingTestHelper {

    public static final FieldMasking.Config DEFAULT = FieldMasking.Config.fromSettings(Settings.EMPTY);
}
