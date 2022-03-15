/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.dlic.dlsfls;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import org.junit.Assert;
import org.opensearch.search.SearchHit;

/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */
public class DlsTermsLookupAsserts {

    /**
     * Asserts that the source map of a search hit contains an field that contains access codes
     * and asserts those access codes contain at least on of the access codes for the user
     * @param sourceMap
     * @param accessCodesKey
     * @param userCodes
     */
    public static void assertAccessCodesMatch(Map<String, Object> sourceMap, String accessCodesKey, Integer[] userCodes) {
        Object field = sourceMap.get(accessCodesKey);
        Assert.assertTrue(sourceMap.toString(), field instanceof Collection<?>);
        Collection<?> documentAccessCodes = (Collection<?>) field;
        // make sure the access codes in the document contain at least one code of the user access codes
        Assert.assertTrue(sourceMap.toString(), documentAccessCodes.removeAll(Arrays.asList(userCodes)));

    }

    /**
     * Extracts the access codes from search hits and compares them with a given collection of
     * access codes. The documents access codes are retrieved for each document from the 'access_codes' field.
     * This method asserts that those access codes contain at least one of the access codes for the user
     * @param searchHits the search hits from the tlqdocuments index
     * @param userCodes the access coded of the user
     */
    public static void assertAccessCodesMatch(Collection<SearchHit> searchHits, Integer[] userCodes) {
        for (SearchHit hit : searchHits) {
            assertAccessCodesMatch(hit.getSourceAsMap(), "access_codes", userCodes);
        }
    }

    /**
     * See above
     * @param searchHits
     * @param userCodes
     */
    public static void assertAccessCodesMatch(SearchHit[] searchHits, Integer[] userCodes) {
        assertAccessCodesMatch(Arrays.asList(searchHits), userCodes);
    }

    /**
     * Checks whether a document from the tlqdocuments index contains a certain value in the bu field
     * @param searchHit
     * @param buCode
     */
    public static void assertBuMatches(SearchHit searchHit, String buCode) {
        Object field = searchHit.getSourceAsMap().get("bu");
        Assert.assertTrue(searchHit.toString(), field instanceof String);
        Assert.assertTrue(searchHit.toString(), ((String) field).equals(buCode));
    }

    /**
     * Checks whether all document from the tlqdocuments index contains a certain value in the bu field
     * @param searchHit
     * @param buCode
     */
    public static void assertBuMatches(SearchHit[] searchHits, String buCode) {
        for (SearchHit searchHit : searchHits) {
            assertBuMatches(searchHit, buCode);
        }
    }

    /**
     * Compares the cluster alias field in search hits with a given alias and fails
     * if the alias name is different
     * @param searchHits
     * @param clusterAlias
     */
    public static void assertAllHitsComeFromCluster(Collection<SearchHit> searchHits, String clusterAlias) {
        assertTrue("Expected cluster alias name to not be null", clusterAlias != null);
        for (SearchHit hit : searchHits) {
            assertTrue("Expected cluster alias in search hit to not be null\n" + hit, hit.getClusterAlias() != null);
            assertTrue(hit.toString(), hit.getClusterAlias().equals(clusterAlias));
        }
    }

    public static void assertAllHitsComeFromCluster(SearchHit[] searchHits, String clusterAlias) {
        assertAllHitsComeFromCluster(Arrays.asList(searchHits), clusterAlias);
    }

    public static void assertAllHitsComeFromLocalCluster(SearchHit[] searchHits) {
        assertAllHitsComeFromLocalCluster(Arrays.asList(searchHits));
    }

    public static void assertAllHitsComeFromLocalCluster(Collection<SearchHit> searchHits) {
        for (SearchHit hit : searchHits) {
            assertTrue(hit.toString(), hit.getClusterAlias() == null);
        }
    }

}
