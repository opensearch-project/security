package org.opensearch.security.privileges;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocRequest;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.resources.ResourceSharingIndexHandler;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

public class ResourceAccessEvaluator {
    private final Set<String> resourceIndices;
    private final ThreadContext threadContext;
    private final ResourceSharingIndexHandler resourceSharingIndexHandler;

    public ResourceAccessEvaluator(
        Set<String> resourceIndices,
        ThreadPool threadPool,
        ResourceSharingIndexHandler resourceSharingIndexHandler
    ) {
        this.resourceIndices = resourceIndices;
        this.threadContext = threadPool.getThreadContext();
        this.resourceSharingIndexHandler = resourceSharingIndexHandler;
    }

    public PrivilegesEvaluatorResponse evaluate(
        final ActionRequest request,
        final String action,
        final PrivilegesEvaluationContext context,
        final PrivilegesEvaluatorResponse presponse
    ) throws IOException {

        if (!(request instanceof DocRequest)) {
            return presponse;
        }

        final UserSubjectImpl userSubject = (UserSubjectImpl) this.threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            presponse.allowed = false;
            return presponse.markComplete();
        }

        DocRequest req = (DocRequest) request;

        // If user was super-admin, the request would have already been granted. So no need to check whether user is admin

        // Creation Request
        // TODO Check if following is the correct way to identify the create request
        if (request instanceof DocWriteRequest<?> && req.id() == null) {
            // check write permissions
            // TODO verif that this can be punted to the regular evaluator since it requires write permissions to the index
            return presponse;
        }



        // if requested index is not a resource sharing index, move on to the next evaluator
        if (!resourceIndices.contains(req.index())) {
            return presponse;
        }

        // Fetch the ResourceSharing document

        CountDownLatch latch = new CountDownLatch(1);

        Set<String> userRoles = new HashSet<>(user.getSecurityRoles());
        Set<String> userBackendRoles = new HashSet<>(user.getRoles());

        this.resourceSharingIndexHandler.fetchSharingInfo(req.index(), req.id(), ActionListener.wrap(document -> {
            if (document == null) {
                presponse.allowed = false; // TODO should we move this to next evaluator if no document is present, probs not since this
                                           // index is protected
                latch.countDown();
                return;
            }

            // If document is public, action is allowed
            // If user is the owner, action is allowed
            if (document.isSharedWithEveryone() || document.isCreatedBy(user.getName())) {
                presponse.allowed = true;
                latch.countDown();
                return;
            }

            Set<String> accessLevels = new HashSet<>();
            accessLevels.addAll(document.fetchAccessLevels(Recipient.USERS, Set.of(user.getName())));
            accessLevels.addAll(document.fetchAccessLevels(Recipient.ROLES, userRoles));
            accessLevels.addAll(document.fetchAccessLevels(Recipient.BACKEND_ROLES, userBackendRoles));

            if (accessLevels.isEmpty()) {
                presponse.allowed = false;
                latch.countDown();
                return;
            }

            // Expand access-levels and check if any match the action supplied
            if (context.getActionPrivileges() instanceof RoleBasedActionPrivileges roleBasedActionPrivileges) {
                Set<String> actions = roleBasedActionPrivileges.flattenedActionGroups().resolve(accessLevels);
                presponse.allowed = actions.contains(action);
                latch.countDown();
            } else {
                // we don't yet support Plugins to access resources
                presponse.allowed = false;
                latch.countDown();
            }

        }, e -> {
            presponse.allowed = false;
            latch.countDown();
        }));
        try {
            latch.await();
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }

        return presponse.markComplete();
    }
}
