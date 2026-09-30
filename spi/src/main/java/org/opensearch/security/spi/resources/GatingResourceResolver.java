/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi.resources;

import org.opensearch.action.DocRequest;
import org.opensearch.core.action.ActionListener;

/**
 * Resolves the resource that governs access to a request, for the case where it is not the one the request names.
 *
 * <p>The evaluator authorizes a request using the type and id the request itself reports. When access is governed by a
 * different resource, and that resource is only known after a read, a plugin would otherwise have to perform the check
 * by hand. alerting's alert comments are the case: an index, update or delete carries an alert or comment id, and the
 * monitor that governs access is known only after reading it.
 *
 * <p>A plugin registers a resolver through {@link ResourceSharingExtension#getGatingResourceResolvers()} for the value
 * its requests report as {@link DocRequest#type()}. When such a request arrives, the evaluator asks the resolver for the
 * gating resource id and authorizes that resource, of {@link #gatingResourceType()}, instead. The request is denied if
 * resolution yields nothing or fails.
 *
 * <p>Notes for implementers:
 * <ul>
 *   <li>{@link #requestType()} must not be a registered resource type. A request of a registered type is authorized
 *       directly against that type, so a resolver claiming the same name is ignored.</li>
 *   <li>The request's own index need not be a resource index, and the document it names need not exist yet, which is
 *       what lets a create be gated by an existing parent.</li>
 *   <li>{@link #resolveGatingResourceId} is called on the transport thread while the request is being authorized, so it
 *       must not block. Perform the read with the plugin's own client, since the requesting user usually holds no
 *       permission on the index being read. Stashing the thread context for that read is safe: the authenticated user is
 *       carried in a persistent header, which survives a stash, so the subsequent access check still sees the caller.</li>
 * </ul>
 */
public interface GatingResourceResolver {

    /**
     * The value that requests handled by this resolver report as {@link DocRequest#type()}.
     *
     * @return the request type this resolver claims
     */
    String requestType();

    /**
     * The registered resource type that governs access to those requests. Resolution only takes place while this type is
     * protected.
     *
     * @return the gating resource type
     */
    String gatingResourceType();

    /**
     * Resolves the id of the resource that governs access to this request.
     *
     * @param request  the request being authorized
     * @param listener notified with the gating resource id; a null or empty id denies the request, as does a failure
     */
    void resolveGatingResourceId(DocRequest request, ActionListener<String> listener);
}
