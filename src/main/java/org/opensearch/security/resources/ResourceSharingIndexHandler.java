/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.resources;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ExceptionsHelper;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.security.spi.resources.sharing.CreatedBy;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.spi.resources.sharing.Recipients;
import org.opensearch.security.spi.resources.sharing.ResourceSharing;
import org.opensearch.security.spi.resources.sharing.ShareWith;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;

/**
 * This class handles the creation and management of the resource sharing index.
 * It provides methods to create the index, index resource sharing entries along with updates and deletion, retrieve shared resources.
 *
 * @opensearch.experimental
 */
public class ResourceSharingIndexHandler {

    private static final Logger LOGGER = LogManager.getLogger(ResourceSharingIndexHandler.class);

    private final Client client;

    private final ThreadPool threadPool;

    @Inject
    public ResourceSharingIndexHandler(final Client client, final ThreadPool threadPool) {
        this.client = client;
        this.threadPool = threadPool;
    }

    public final static Map<String, Object> INDEX_SETTINGS = Map.of(
        "index.number_of_shards",
        1,
        "index.auto_expand_replicas",
        "0-all",
        "index.hidden",
        "true"
    );

    /**
     * Creates the resource sharing index if it doesn't already exist.
     * This method initializes the index with predefined mappings and settings
     * for storing resource sharing information.
     * The index will be created with the following structure:
     * - source_idx (keyword): The source index containing the original document
     * - resource_id (keyword): The ID of the shared resource
     * - created_by (object): Information about the user who created the sharing
     * - user (keyword): Username of the creator
     * - share_with (object): Access control configuration for shared resources
     * - [action-group] (object): Name of the action-group
     * - users (array): List of users with access
     * - roles (array): List of roles with access
     * - backend_roles (array): List of backend roles with access
     *
     * @throws RuntimeException if there are issues reading/writing index settings
     *                          or communicating with the cluster
     */

    public void createResourceSharingIndicesIfAbsent(Set<String> resourceIndices) {
        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            for (String resourceIndex : resourceIndices) {
                String resourceSharingIndex = getSharingIndex(resourceIndex);
                CreateIndexRequest cir = new CreateIndexRequest(resourceSharingIndex).settings(INDEX_SETTINGS).waitForActiveShards(1);
                ActionListener<CreateIndexResponse> cirListener = ActionListener.wrap(response -> {
                    ctx.restore();
                    LOGGER.info("Resource sharing index {} created.", resourceSharingIndex);
                }, (failResponse) -> {
                    /* Index already exists, ignore and continue */
                    LOGGER.info("Index {} already exists.", resourceSharingIndex);
                });
                this.client.admin().indices().create(cir, cirListener);
            }
        }
    }

    public static String getSharingIndex(String resourceIndex) {
        return resourceIndex + "-sharing";
    }

    /**
     * Updates the visibility of a resource document by replacing its {@code principals} field
     * with the provided list of principals. The update is executed immediately with
     * {@link WriteRequest.RefreshPolicy#IMMEDIATE} to ensure the change is visible in subsequent
     * searches.
     * <p>
     * The supplied {@link ActionListener} will be invoked with the {@link UpdateResponse}
     * on success, or with an exception on failure.
     *
     * @param resourceId     the unique identifier of the resource document to update
     * @param resourceIndex  the name of the index containing the resource
     * @param principals     the list of principals (e.g. {@code user:alice}, {@code role:admin})
     *                       that should be assigned to the resource
     * @param listener       callback that will be notified with the update response or an error
     */
    public void updateResourceVisibility(
        String resourceId,
        String resourceIndex,
        List<String> principals,
        ActionListener<UpdateResponse> listener
    ) {
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            UpdateRequest ur = client.prepareUpdate(resourceIndex, resourceId)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setDoc(Map.of("all_shared_principals", principals))
                .setId(resourceId)
                .request();

            ActionListener<UpdateResponse> urListener = ActionListener.wrap(response -> {
                ctx.restore();
                LOGGER.info(
                    "Successfully updated visibility of resource {} in index {} to principals {}.",
                    resourceIndex,
                    resourceId,
                    principals
                );
                listener.onResponse(response);
            }, (e) -> {
                LOGGER.error("Failed to update visibility in [{}] for resource [{}]", resourceIndex, resourceId, e);
                listener.onFailure(e);
            });
            client.update(ur, urListener);
        }
    }

    /**
     * Creates or updates a resource sharing record in the dedicated resource sharing index.
     * This method handles the persistence of sharing metadata for resources, including
     * the creator information and sharing permissions.
     *
     * @param resourceId    The unique identifier of the resource being shared
     * @param resourceIndex The source index where the original resource is stored
     * @param createdBy     Object containing information about the user creating/updating the sharing
     * @param shareWith     Object containing the sharing permissions' configuration. Can be null for initial creation.
     *                      When provided, it should contain the access control settings for different groups:
     *                      {
     *                      "action-group": {
     *                      "users": ["user1", "user2"],
     *                      "roles": ["role1", "role2"],
     *                      "backend_roles": ["backend_role1"]
     *                      }
     *                      }
     * @param listener Returns resourceSharing object if the operation was successful, exception otherwise
     * @throws IOException if there are issues with index operations or JSON processing
     */
    public void indexResourceSharing(
        String resourceId,
        String resourceIndex,
        CreatedBy createdBy,
        ShareWith shareWith,
        ActionListener<ResourceSharing> listener
    ) throws IOException {
        // TODO: Once stashContext is replaced with switchContext this call will have to be modified
        String resourceSharingIndex = getSharingIndex(resourceIndex);
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            ResourceSharing entry = new ResourceSharing(resourceId, createdBy, shareWith);

            IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .setSource(entry.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .setOpType(DocWriteRequest.OpType.CREATE) // only create if an entry doesn't exist
                .setId(resourceId)
                .request();

            ActionListener<IndexResponse> irListener = ActionListener.wrap(idxResponse -> {
                ctx.restore();
                LOGGER.info("Successfully created {} entry for resource {} in index {}.", resourceSharingIndex, resourceId, resourceIndex);
                updateResourceVisibility(
                    resourceId,
                    resourceIndex,
                    List.of("user:" + createdBy.getUsername()),
                    ActionListener.wrap((updateResponse) -> {
                        LOGGER.debug(
                            "postUpdate: Successfully updated visibility for resource {} within index {}",
                            resourceId,
                            resourceIndex
                        );
                        listener.onResponse(entry);
                    }, (e) -> {
                        LOGGER.error("Failed to create principals field in [{}] for resource [{}]", resourceIndex, resourceId, e);
                        listener.onResponse(entry);
                    })
                );
            }, (e) -> {
                if (ExceptionsHelper.unwrapCause(e) instanceof VersionConflictEngineException) {
                    // already exists → skipping
                    LOGGER.debug("Entry for [{}] already exists in [{}], skipping", resourceId, resourceSharingIndex);
                    listener.onResponse(entry);
                } else {
                    LOGGER.error("Failed to create entry in [{}] for resource [{}]", resourceSharingIndex, resourceId, e);
                    listener.onFailure(e);
                }
            });
            client.index(ir, irListener);
        }
    }

    /**
     * Fetches a specific resource sharing document by its resource ID and system resourceIndex.
     * This method performs an exact match search and parses the result into a ResourceSharing object.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Validates input parameters for null/empty values</li>
     *   <li>Creates a search request with a bool query for exact matching</li>
     *   <li>Executes the search with a limit of 1 document</li>
     *   <li>Parses the result using XContent parser if found</li>
     *   <li>Returns null if no matching document exists</li>
     * </ol>
     *
     * <p>Example query structure:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": "resource_index_name" } },
     *         { "term": { "resource_id": "resource_id_value" } }
     *       ]
     *     }
     *   },
     *   "size": 1
     * }
     * </pre>
     *
     * @param resourceIndex       The source resourceIndex to match against the source_idx field
     * @param resourceId  The resource ID to fetch. Must exactly match the resource_id field
     * @param listener    The listener to be notified when the operation completes.
     *                    The listener receives the parsed ResourceSharing object or null if not found
     * @throws IllegalArgumentException if resourceIndex or resourceId is null or empty
     * @throws RuntimeException         if the search operation fails or parsing errors occur,
     *                                  wrapping the underlying exception
     * @apiNote This method:
     * <ul>
     *   <li>Uses term queries for exact matching</li>
     *   <li>Expects only one matching document per resource ID</li>
     *   <li>Uses XContent parsing for consistent object creation</li>
     *   <li>Returns null instead of throwing exceptions for non-existent documents</li>
     *   <li>Provides detailed logging for troubleshooting</li>
     * </ul>
     * <p>
     * Example usage:
     * <pre>
     * ResourceSharing sharing = fetchDocumentById("myIndex", "resource123");
     * if (sharing != null) {
     *     // Process the resource sharing object
     * }
     * </pre>
     */
    public void fetchSharingInfo(String resourceIndex, String resourceId, ActionListener<ResourceSharing> listener) {
        if (StringUtils.isBlank(resourceIndex) || StringUtils.isBlank(resourceId)) {
            listener.onFailure(new IllegalArgumentException("resourceIndex and resourceId must not be null or empty"));
            return;
        }
        String resourceSharingIndex = getSharingIndex(resourceIndex);
        LOGGER.debug("Fetching document from {}, matching resource_id: {}", resourceSharingIndex, resourceId);

        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {

            GetRequest getRequest = new GetRequest(resourceSharingIndex).id(resourceId);

            client.get(getRequest, ActionListener.wrap(getResponse -> {
                ctx.restore();
                try {
                    if (!getResponse.isExists()) {
                        LOGGER.debug(
                            "No document found in {} matching resource_id: {} and source_idx {}",
                            resourceSharingIndex,
                            resourceId,
                            resourceIndex
                        );
                        listener.onResponse(null);
                        return;
                    }
                    try (
                        XContentParser parser = XContentType.JSON.xContent()
                            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, getResponse.getSourceAsString())
                    ) {
                        parser.nextToken();
                        ResourceSharing resourceSharing = ResourceSharing.fromXContent(parser);
                        resourceSharing.setResourceId(getResponse.getId());

                        LOGGER.debug(
                            "Successfully fetched document from {} matching resource_id: {} and source_idx: {}",
                            resourceSharingIndex,
                            resourceId,
                            resourceIndex
                        );

                        listener.onResponse(resourceSharing);
                    }
                } catch (Exception e) {
                    String failureResponse = "Failed to parse document matching resource_id: "
                        + resourceId
                        + " and source_idx: "
                        + resourceIndex
                        + " from "
                        + resourceSharingIndex;
                    LOGGER.error(failureResponse, e);
                    listener.onFailure(new OpenSearchStatusException(failureResponse, RestStatus.INTERNAL_SERVER_ERROR));
                }
            }, exception -> {
                String failureResponse = "Something went wrong while fetching resource sharing record for resource_id: "
                    + resourceId
                    + " and source_idx: "
                    + resourceIndex
                    + " from "
                    + resourceSharingIndex;
                LOGGER.error(failureResponse, exception);
                listener.onFailure(new OpenSearchStatusException(failureResponse, RestStatus.INTERNAL_SERVER_ERROR));
            }));

        }
    }

    /**
     * Updates the sharing configuration for an existing resource in the resource sharing index.
     * NOTE: This method only grants new access. To remove access use {@link #revoke(String, String, ShareWith, ActionListener)}
     * This method modifies the sharing permissions for a specific resource identified by its
     * resource ID and source index.
     *
     * @param resourceId      The unique identifier of the resource whose sharing configuration needs to be updated
     * @param resourceIndex   The source index where the original resource is stored
     * @param shareWith       Updated sharing configuration object containing access control settings:
     *                        {
     *                        "action-group": {
     *                        "users": ["user1", "user2"],
     *                        "roles": ["role1", "role2"],
     *                        "backend_roles": ["backend_role1"]
     *                        }
     *                        }
     * @param listener        Listener to be notified when the operation completes
     * @throws RuntimeException if there's an error during the update operation
     */
    public void share(String resourceId, String resourceIndex, ShareWith shareWith, ActionListener<ResourceSharing> listener) {
        StepListener<ResourceSharing> sharingInfoListener = new StepListener<>();

        // Fetch resource sharing doc
        fetchSharingInfo(resourceIndex, resourceId, sharingInfoListener);

        // build update script
        sharingInfoListener.whenComplete(sharingInfo -> {
            if (sharingInfo == null) {
                LOGGER.debug("No sharing record found for resource {}", resourceId);
                listener.onResponse(null);
                return;
            }
            for (String accessLevel : shareWith.accessLevels()) {
                Recipients target = shareWith.atAccessLevel(accessLevel);

                sharingInfo.share(accessLevel, target);
            }

            String resourceSharingIndex = getSharingIndex(resourceIndex);
            try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
                IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                    .setId(sharingInfo.getResourceId())
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .setSource(sharingInfo.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .setOpType(DocWriteRequest.OpType.INDEX)
                    .request();

                ActionListener<IndexResponse> irListener = ActionListener.wrap(idxResponse -> {
                    ctx.restore();
                    LOGGER.info(
                        "Successfully updated {} entry for resource {} in index {}.",
                        resourceSharingIndex,
                        resourceId,
                        resourceIndex
                    );
                    updateResourceVisibility(
                        resourceId,
                        resourceIndex,
                        sharingInfo.getAllPrincipals(),
                        ActionListener.wrap((updateResponse) -> {
                            LOGGER.debug("Successfully updated visibility for resource {} within index {}", resourceId, resourceIndex);
                            listener.onResponse(sharingInfo);
                        }, (e) -> {
                            LOGGER.error("Failed to update principals field in [{}] for resource [{}]", resourceIndex, resourceId, e);
                            listener.onResponse(sharingInfo);
                        })
                    );
                }, (failResponse) -> {
                    LOGGER.error(failResponse.getMessage());
                    listener.onFailure(failResponse);
                });
                client.index(ir, irListener);
            }
        }, listener::onFailure);
    }

    /**
     * Revokes access for specified entities from a resource sharing document. This method removes the specified
     * entities (users, roles, or backend roles) from the existing sharing configuration while preserving other
     * sharing settings.
     *
     * <p>The method performs the following steps:
     * <ol>
     *   <li>Fetches the existing document</li>
     *   <li>Removes specified entities from their respective lists in all sharing groups</li>
     *   <li>Updates the document if modifications were made</li>
     *   <li>Returns the updated resource sharing configuration</li>
     * </ol>
     *
     * <p>Example document structure:
     * <pre>
     * {
     *   "source_idx": "resource_index_name",
     *   "resource_id": "resource_id",
     *   "share_with": {
     *     "action-group": {
     *       "users": ["user1", "user2"],
     *       "roles": ["role1", "role2"],
     *       "backend_roles": ["backend_role1"]
     *     }
     *   }
     * }
     * </pre>
     *
     * @param resourceId      The ID of the resource from which to revoke access
     * @param resourceIndex   The name of the system index where the resource exists
     * @param revokeAccess    A map containing entity types (USER, ROLE, BACKEND_ROLE) and their corresponding
     *                        values to be removed from the sharing configuration
     * @param listener        Listener to be notified when the operation completes
     * @throws IllegalArgumentException if resourceId, resourceIndex is null/empty, or if revokeAccess is null/empty
     * @throws RuntimeException         if the update operation fails or encounters an error
     * @apiNote This method modifies the existing document. If no modifications are needed (i.e., specified
     * entities don't exist in the current configuration), the original document is returned unchanged.
     * @see Recipient
     * @see ResourceSharing
     */
    public void revoke(String resourceId, String resourceIndex, ShareWith revokeAccess, ActionListener<ResourceSharing> listener) {
        if (StringUtils.isBlank(resourceId) || StringUtils.isBlank(resourceIndex) || revokeAccess == null) {
            listener.onFailure(new IllegalArgumentException("resourceId, resourceIndex, and revokeAccess must not be null or empty"));
            return;
        }
        String resourceSharingIndex = getSharingIndex(resourceIndex);

        StepListener<ResourceSharing> sharingInfoListener = new StepListener<>();

        // Fetch the current ResourceSharing document
        fetchSharingInfo(resourceIndex, resourceId, sharingInfoListener);

        // build revoke script
        sharingInfoListener.whenComplete(sharingInfo -> {

            assert sharingInfo != null;
            for (String accessLevel : revokeAccess.accessLevels()) {
                Recipients target = revokeAccess.atAccessLevel(accessLevel);
                LOGGER.debug(
                    "Revoking access for resource {} in {} for entities: {} and accessLevel: {}",
                    resourceId,
                    resourceIndex,
                    target,
                    accessLevel
                );

                sharingInfo.revoke(accessLevel, target);
            }
            try (ThreadContext.StoredContext ctx = threadPool.getThreadContext().stashContext()) {
                IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                    .setId(sharingInfo.getResourceId())
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .setSource(sharingInfo.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .setOpType(DocWriteRequest.OpType.INDEX)
                    .request();

                ActionListener<IndexResponse> irListener = ActionListener.wrap(idxResponse -> {
                    ctx.restore();
                    LOGGER.info("Successfully revoked access of {} to resource {} in index {}.", revokeAccess, resourceId, resourceIndex);
                    updateResourceVisibility(
                        resourceId,
                        resourceIndex,
                        sharingInfo.getAllPrincipals(),
                        ActionListener.wrap((updateResponse) -> {
                            LOGGER.debug("Successfully updated visibility for resource {} within index {}", resourceId, resourceIndex);
                            listener.onResponse(sharingInfo);
                        }, (e) -> {
                            LOGGER.error("Failed to update principals field in [{}] for resource [{}]", resourceIndex, resourceId, e);
                            listener.onResponse(sharingInfo);
                        })
                    );
                }, (failResponse) -> {
                    LOGGER.error(failResponse.getMessage());
                    listener.onFailure(failResponse);
                });
                client.index(ir, irListener);
            }
        }, listener::onFailure);
    }

    /**
     * Fetch existing share_with, apply the patch ops in-memory, and update the sharing record.
     * Two ops are supported:
     * 1. share_with -> upgrade or downgrade access; share with new entities
     * 2. revoke -> revoke access for existing entities
     * @param resourceId    id of the resource to apply the patch to
     * @param resourceIndex name of the index where resource is present
     * @param add  the recipients to be shared with
     * @param revoke  the recipients to be revoked with
     * @param listener      listener to be notified in case of success or failure
     */
    public void patchSharingInfo(
        String resourceId,
        String resourceIndex,
        ShareWith add,
        ShareWith revoke,
        ActionListener<ResourceSharing> listener
    ) {

        StepListener<ResourceSharing> sharingInfoListener = new StepListener<>();
        String resourceSharingIndex = getSharingIndex(resourceIndex);

        // Fetch the current ResourceSharing document
        fetchSharingInfo(resourceIndex, resourceId, sharingInfoListener);

        // Apply patch and update the document
        sharingInfoListener.whenComplete(resourceSharing -> {
            ShareWith updatedShareWith = resourceSharing.getShareWith();
            if (updatedShareWith == null) {
                updatedShareWith = new ShareWith(new HashMap<>());
            }
            if (add != null) {
                updatedShareWith = updatedShareWith.add(add);
            }
            if (revoke != null) {
                updatedShareWith = updatedShareWith.revoke(revoke);
            }

            ResourceSharing updatedSharingInfo = new ResourceSharing(resourceId, resourceSharing.getCreatedBy(), updatedShareWith);

            try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
                // update the record
                IndexRequest ir = client.prepareIndex(resourceSharingIndex)
                    .setId(resourceId)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .setSource(updatedSharingInfo.toXContent(jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .setOpType(DocWriteRequest.OpType.INDEX)
                    .request();

                client.index(ir, ActionListener.wrap(idxResponse -> {
                    ctx.restore();
                    LOGGER.info(
                        "Successfully updated {} resource sharing info for resource {} in index {}.",
                        resourceSharingIndex,
                        resourceId,
                        resourceIndex
                    );

                    listener.onResponse(updatedSharingInfo);
                }, (e) -> {
                    LOGGER.error(e.getMessage());
                    listener.onFailure(e);
                }));
            }
        }, listener::onFailure);
    }

    /**
     * Deletes resource sharing records that match the specified source index and resource ID.
     * This method performs a delete-by-query operation in the resource sharing index.
     *
     * <p>The method executes the following steps:
     * <ol>
     *   <li>Creates a delete-by-query request with a bool query</li>
     *   <li>Matches documents based on exact source index and resource ID</li>
     *   <li>Executes the delete operation with immediate refresh</li>
     *   <li>Returns the success/failure status based on deletion results</li>
     * </ol>
     *
     * <p>Example document structure that will be deleted:
     * <pre>
     * {
     *   "source_idx": "source_index_name",
     *   "resource_id": "resource_id_value",
     *   "share_with": {
     *     // sharing configuration
     *   }
     * }
     * </pre>
     *
     * @param resourceIndex  The source index to match in the query (exact match)
     * @param resourceId The resource ID to match in the query (exact match)
     * @param listener   The listener to be notified when the operation completes
     * @throws IllegalArgumentException if resourceIndex or resourceId is null/empty
     * @throws RuntimeException         if the delete operation fails or encounters an error
     * @implNote The delete operation uses a bool query with two must clauses to ensure exact matching:
     * <pre>
     * {
     *   "query": {
     *     "bool": {
     *       "must": [
     *         { "term": { "source_idx": resourceIndex } },
     *         { "term": { "resource_id": resourceId } }
     *       ]
     *     }
     *   }
     * }
     * </pre>
     */
    public void deleteResourceSharingRecord(String resourceId, String resourceIndex, ActionListener<Boolean> listener) {
        String resourceSharingIndex = getSharingIndex(resourceIndex);
        LOGGER.debug(
            "Deleting documents asynchronously from {} where source_idx = {} and resource_id = {}",
            resourceSharingIndex,
            resourceIndex,
            resourceId
        );

        // Delete it as super-admin. This method is only called in postDelete handler for resource-index
        try (ThreadContext.StoredContext ctx = this.threadPool.getThreadContext().stashContext()) {
            DeleteRequest deleteRequest = new DeleteRequest(resourceSharingIndex, resourceId);

            client.delete(deleteRequest, ActionListener.wrap(deleteResponse -> {
                ctx.restore();
                boolean deleted = DocWriteResponse.Result.DELETED.equals(deleteResponse.getResult());
                if (deleted) {
                    LOGGER.debug("Successfully deleted {} documents from {}", deleted, resourceSharingIndex);
                    listener.onResponse(true);
                } else {
                    LOGGER.debug(
                        "No documents found to delete in {} for source_idx: {} and resource_id: {}",
                        resourceSharingIndex,
                        resourceIndex,
                        resourceId
                    );
                    // No documents were deleted
                    listener.onResponse(false);
                }
            }, failResponse -> {
                LOGGER.error("Failed to delete documents from {}", resourceSharingIndex, failResponse);
                listener.onFailure(failResponse);
            }));

        }
    }

}
