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
 *   <li>{@link #requestType()} must declare a type of the plugin's own. It may not be a registered resource type, since
 *       a request of a registered type is authorized against that type directly, and it may not be {@code "indices"},
 *       which is what {@link DocRequest#type()} reports for a request that declares nothing: a resolver claiming it would
 *       be consulted for every such request in the cluster. Both are rejected at registration.</li>
 *   <li>The request's own index need not be a resource index, and the document it names need not exist yet, which is what
 *       lets a create be gated by an existing parent. A create may report a null {@link DocRequest#id()}; the resolver
 *       receives the whole request and reads whatever field carries the link to the governing resource.</li>
 *   <li>A core {@link org.opensearch.action.DocWriteRequest} or {@link org.opensearch.action.get.GetRequest} cannot be
 *       gated this way. Those are index actions and the evaluator declines them before any resolver is consulted.</li>
 *   <li>{@link #resolveGatingResourceId} is called on the transport thread while the request is being authorized, so it
 *       must not block. Perform the read with the plugin's own client, since the requesting user usually holds no
 *       permission on the index being read.</li>
 *   <li><b>Restore the caller's context before completing the listener.</b> The access check that follows, and the
 *       transport action after it, run on whatever context the listener is invoked with. Reading as the plugin is fine,
 *       but hand the caller's context back first: {@code PluginClient} in the sample plugin shows the pattern, wrapping
 *       the listener in {@code ActionListener.runBefore(listener, storedContext::restore)}. The authenticated user itself
 *       travels in a persistent header and survives a stash, so the check would still identify the caller, but the
 *       downstream action would run with the plugin's transient state.</li>
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
