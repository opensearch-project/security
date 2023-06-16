/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.test.framework.matcher;

import org.hamcrest.Matcher;

import org.opensearch.action.delete.DeleteResponse;

public class DeleteResponseMatchers {

    private DeleteResponseMatchers() {}

    public static Matcher<DeleteResponse> isSuccessfulDeleteResponse() {
        return new SuccessfulDeleteResponseMatcher();
    }
}
