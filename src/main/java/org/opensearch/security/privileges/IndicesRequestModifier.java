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

/**
 * Provides methods to modify the local indices of an IndicesRequest. All methods use the ResolvedIndices metadata object
 * to make sure that remote indices are properly retained.
 * <p>
 * We need the distinction between local indices and remote indices because authorization on remote indices is performed
 * on the remote cluster - thus, we can leave them here just as they are.
 */
public class IndicesRequestModifier {

    public boolean setLocalIndices(ActionRequest targetRequest, ResolvedIndices resolvedIndices, Collection<String> newIndices) {
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
                if (replaceable.indicesOptions().expandWildcardsOpen() || replaceable.indicesOptions().expandWildcardsClosed()) {
                    // If the request expands wildcards, we use an index expression which resolves to no indices
                    replaceable.indices(".none*,-*");
                    return true;
                } else if (replaceable.indicesOptions().allowNoIndices()) {
                    // If the request does not expand wildcards, we use a index name that cannot exist.
                    replaceable.indices("-.none*");
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
