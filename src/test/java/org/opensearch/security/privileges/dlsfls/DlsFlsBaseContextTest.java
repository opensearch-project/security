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

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.privileges.PrivilegesConfiguration;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

public class DlsFlsBaseContextTest {

    @Test
    public void hybridQueryFilterDoesNotMarkReaderLevelDlsAsDone() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        DlsFlsBaseContext context = new DlsFlsBaseContext(mock(PrivilegesConfiguration.class), threadContext, mock(AdminDNs.class));

        threadContext.putHeader(
            ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE,
            ConfigConstants.OPENDISTRO_SECURITY_HYBRID_QUERY_DLS_DONE
        );

        assertThat(context.isDlsQueryFilterApplied(), is(true));
        assertThat(context.isDlsDoneOnFilterLevel(), is(false));
    }

    @Test
    public void filterLevelDlsMarkerDoesNotMarkHybridQueryFilterAsApplied() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        DlsFlsBaseContext context = new DlsFlsBaseContext(mock(PrivilegesConfiguration.class), threadContext, mock(AdminDNs.class));

        threadContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE, "true");

        assertThat(context.isDlsDoneOnFilterLevel(), is(true));
        assertThat(context.isDlsQueryFilterApplied(), is(false));
    }
}
