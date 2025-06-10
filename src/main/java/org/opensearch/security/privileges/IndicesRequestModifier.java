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
package org.opensearch.security.privileges;

import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.IndicesRequest;
import org.opensearch.cluster.metadata.ResolvedIndices;

public class IndicesRequestModifier {

    public boolean reduceLocalIndices(ActionRequest targetRequest, ResolvedIndices resolvedIndices, Collection<String> newIndices) {
        if (newIndices.isEmpty()) {
            return setLocalIndicesToEmpty(targetRequest, resolvedIndices);
        }

        if (targetRequest instanceof IndicesRequest.Replaceable) {
            ((IndicesRequest.Replaceable) targetRequest).indices(concat(newIndices, resolvedIndices.remote().asRawExpressions()));
            return true;
        } else {
            return false;
        }
    }

    public boolean setLocalIndicesToEmpty(ActionRequest targetRequest, ResolvedIndices resolvedIndices) {
        if (targetRequest instanceof IndicesRequest.Replaceable replaceable) {
            if (resolvedIndices.remote().isEmpty()) {
                if (replaceable.indicesOptions().expandWildcardsOpen()
                    || replaceable.indicesOptions().expandWildcardsClosed()
                    || replaceable.indicesOptions().expandWildcardsHidden()) {
                    // If the request expands wildcards, we use an index expression which resolves to no indices
                    // This expression cannot resolve to anything because indices with a leading underscore are not allowed
                    replaceable.indices("_empty*,-*");
                    return true;
                } else if (replaceable.indicesOptions().allowNoIndices()) {
                    // If the request does not expand wildcards, we have to look for two different conditions due to
                    // a slightly odd behavior of IndexNameExpressionResolver:
                    // https://github.com/opensearch-project/OpenSearch/blob/afb08a071269b234936b778f62800bded0e5ea7a/server/src/main/java/org/opensearch/cluster/metadata/IndexNameExpressionResolver.java#L249
                    // For allowNoIndices(), we just select a non-existing index. Again, index names with leading
                    // underscores never exist.
                    replaceable.indices("_empty");
                    return true;
                } else if (replaceable.indicesOptions().ignoreUnavailable()) {
                    // Second case for the special behavior of IndexNameExpressionResolver:
                    replaceable.indices("_empty", "-_empty*");
                    return true;
                } else {
                    // In this case, we cannot perform replacement. But it also won't be necessary due to the
                    // semantics of the feature
                    return false;
                }
            } else {
                // If we have remote indices, things get much easier
                replaceable.indices(resolvedIndices.remote().asRawExpressionsArray());
                return true;
            }
        } else {
            return false;
        }
    }

    private String[] concat(Collection<String> local, List<String> remote) {
        return Stream.concat(local.stream(), remote.stream()).toArray(String[]::new);
    }

}
