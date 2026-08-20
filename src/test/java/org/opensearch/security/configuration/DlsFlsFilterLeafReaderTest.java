/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file to be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.configuration;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class DlsFlsFilterLeafReaderTest {

    private static final String SEARCH_ACTION = "indices:data/read/search[phase/query]";

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
}
