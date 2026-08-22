/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file to be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.configuration;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.support.ConfigConstants;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThrows;

public class DlsFlsFilterLeafReaderTest {

    private static final String SEARCH_ACTION = "indices:data/read/search[phase/query]";

    @Test
    public void identifiesHybridQueryDlsCompletionState() {
        ThreadContext unmarkedContext = new ThreadContext(Settings.EMPTY);
        ThreadContext filterLevelContext = new ThreadContext(Settings.EMPTY);
        filterLevelContext.putHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE, "true");
        ThreadContext hybridContext = new ThreadContext(Settings.EMPTY);
        hybridContext.putHeader(
            ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE,
            ConfigConstants.OPENDISTRO_SECURITY_HYBRID_QUERY_DLS_DONE
        );

        assertThat(DlsFlsFilterLeafReader.isDlsQueryFilterApplied(unmarkedContext), is(false));
        assertThat(DlsFlsFilterLeafReader.isDlsQueryFilterApplied(filterLevelContext), is(false));
        assertThat(DlsFlsFilterLeafReader.isDlsQueryFilterApplied(hybridContext), is(true));
    }

    @Test
    public void appliesDlsToReaderWhenHybridQueryFilterWasApplied() {
        assertThat(DlsFlsFilterLeafReader.shouldApplyDlsToReader(false, false, true, SEARCH_ACTION), is(true));
    }

    @Test
    public void doesNotApplyDlsToReaderForRegularSearch() {
        assertThat(DlsFlsFilterLeafReader.shouldApplyDlsToReader(false, false, false, SEARCH_ACTION), is(false));
    }

    @Test
    public void appliesDlsToReaderForSuggestAndParentChildSearches() {
        assertThat(DlsFlsFilterLeafReader.shouldApplyDlsToReader(true, false, false, SEARCH_ACTION), is(true));
        assertThat(DlsFlsFilterLeafReader.shouldApplyDlsToReader(false, true, false, SEARCH_ACTION), is(true));
    }

    @Test
    public void appliesDlsToReaderForNonSearchActions() {
        assertThat(DlsFlsFilterLeafReader.shouldApplyDlsToReader(false, false, false, "indices:data/read/get"), is(true));
    }

    @Test
    public void rejectsMissingActionWhenReaderDlsIsNotOtherwiseRequired() {
        assertThrows(AssertionError.class, () -> DlsFlsFilterLeafReader.shouldApplyDlsToReader(false, false, false, null));
    }
}
