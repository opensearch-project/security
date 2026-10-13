/*
* SPDX-License-Identifier: Apache-2.0
*/

package org.opensearch.security.test.helper.cluster;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class ClusterHelperTests {

    @Test
    public void usesLegacyForkNumberWhenPresent() {
        assertThat(ClusterHelper.getPortRangeNumber("test_3", "8"), is(3));
    }

    @Test
    public void usesGradleWorkerWhenLegacyForkNumberIsMissing() {
        assertThat(ClusterHelper.getPortRangeNumber(null, "8"), is(8));
    }

    @Test
    public void keepsPortRangeWithinAvailablePortSpace() {
        assertThat(ClusterHelper.getPortRangeNumber(null, "1000"), is(4));
    }

    @Test
    public void fallsBackToGradleWorkerForUnrecognisedLegacyForkId() {
        assertThat(ClusterHelper.getPortRangeNumber("not-a-worker", "4"), is(4));
    }
}
