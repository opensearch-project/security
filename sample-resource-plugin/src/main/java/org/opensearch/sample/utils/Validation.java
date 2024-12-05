/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.sample.utils;

import java.util.Arrays;
import java.util.Set;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.sample.SampleResourceScope;

public class Validation {
    public static ActionRequestValidationException validateScopes(Set<String> scopes) {
        for (String s : scopes) {
            try {
                SampleResourceScope.valueOf(s);
            } catch (IllegalArgumentException | NullPointerException e) {
                ActionRequestValidationException exception = new ActionRequestValidationException();
                exception.addValidationError(
                    "Invalid scope: " + s + ". Scope must be one of: " + Arrays.toString(SampleResourceScope.values())
                );
                return exception;
            }
        }
        return null;
    }
}
