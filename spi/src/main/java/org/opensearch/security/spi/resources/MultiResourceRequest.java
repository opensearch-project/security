/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import java.util.Collection;

import org.opensearch.action.DocRequest;

/**
 * A transport request that operates on more than one shareable resource of a single type.
 *
 * <p>The counterpart of {@link DocRequest}, which names one document. A request implementing this interface reports its
 * ids through {@link #ids()}, and the evaluator authorizes each of them: the request is allowed only if the user holds
 * the requested action on every id. It is deliberately not a {@link DocRequest}, since a request naming several
 * resources has no single id to report; the evaluator accounts for both interfaces and treats them the same way from
 * there on.
 *
 * <p>All ids must be of the type returned by {@link #type()} and live in the index returned by {@link #index()}. A
 * request carrying ids of more than one type cannot be evaluated this way and should be split.
 *
 * <p>A collection that is empty, or that contains a null or empty id, is not evaluated: the request falls through to the
 * regular privileges evaluator, as a blank {@link DocRequest#id()} does today. A plugin whose request means "all
 * resources" therefore still filters its own results.
 */
public interface MultiResourceRequest {

    /**
     * The index holding the resources this request operates on.
     *
     * @return the index name
     */
    String index();

    /**
     * The shareable resource type of every id this request names. Must match the action name prefix in the same way
     * {@link DocRequest#type()} does.
     *
     * @return the resource type
     */
    String type();

    /**
     * The ids of the resources this request operates on.
     *
     * @return the resource ids; must be non-empty and free of blank entries to be evaluated
     */
    Collection<String> ids();
}
