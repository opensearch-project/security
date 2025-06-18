package org.opensearch.security.privileges;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.security.auth.UserSubjectImpl;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.resources.ResourceSharingIndexHandler;
import org.opensearch.security.spi.resources.sharing.Recipient;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

public class ResourceAccessEvaluator {
    private static final Logger log = LogManager.getLogger(ResourceAccessEvaluator.class);

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

        // TODO: Check whether resource access should be disabled system index protection is off

        // TODO need to check whether "cluster:" perms should be handled heeyah
        if (!(request instanceof DocRequest req)) {
            return presponse;
        }

        log.debug("Evaluating resource access");

        final UserSubjectImpl userSubject = (UserSubjectImpl) this.threadContext.getPersistent(
            ConfigConstants.OPENDISTRO_SECURITY_AUTHENTICATED_USER
        );
        final User user = (userSubject == null) ? null : userSubject.getUser();

        if (user == null) {
            presponse.allowed = false;
            log.debug("User is not authenticated, returning unauthorized");
            return presponse.markComplete();
        }

        // If user was super-admin, the request would have already been granted. So no need to check whether user is admin

        // Creation Request
        // TODO Check if following is the correct way to identify the create request
        if (req.id() == null) {
            // check write permissions
            // TODO verify that this can be punted to the regular evaluator since it requires write permissions to the index
            log.debug("Request id is null, request is of type {}", req.getClass().getName());
            return presponse;
        }

        // if requested index is not a resource sharing index, move on to the next evaluator
        if (!resourceIndices.contains(req.index())) {
            log.debug("Request index {} is not a protected resource index", req.index());
            return presponse;
        }

        // Fetch the ResourceSharing document
        CountDownLatch latch = new CountDownLatch(1);

        Set<String> userRoles = new HashSet<>(user.getSecurityRoles());
        Set<String> userBackendRoles = new HashSet<>(user.getRoles());

        AtomicBoolean shouldMarkAsComplete = new AtomicBoolean(false);
        this.resourceSharingIndexHandler.fetchSharingInfo(req.index(), req.id(), ActionListener.wrap(document -> {
            if (document == null) {
                // TODO check whether we should mark response as not allowed. At present, it just returns incomplete response and hence is
                // delegated to next evaluator
                log.debug("No resource sharing record found for resource {} and index {}, skipping evaluation.", req.id(), req.index());
                latch.countDown();
                return;
            }

            // If document is public, action is allowed
            // If user is the owner, action is allowed
            if (document.isSharedWithEveryone() || document.isCreatedBy(user.getName())) {
                presponse.allowed = true;
                shouldMarkAsComplete.set(true);
                String message = document.isSharedWithEveryone()
                    ? "Publicly shared resource"
                    : "User " + user.getName() + " is the owner of the resource";
                log.debug("{} {}, granting access.", message, req.id());
                latch.countDown();
                return;
            }

            Set<String> accessLevels = new HashSet<>();
            accessLevels.addAll(document.fetchAccessLevels(Recipient.USERS, Set.of(user.getName())));
            accessLevels.addAll(document.fetchAccessLevels(Recipient.ROLES, userRoles));
            accessLevels.addAll(document.fetchAccessLevels(Recipient.BACKEND_ROLES, userBackendRoles));

            if (accessLevels.isEmpty()) {
                presponse.allowed = false;
                log.debug("Resource {} is not shared with user {}", req.id(), user.getName());
                shouldMarkAsComplete.set(true);
                latch.countDown();
                return;
            }

            // Expand access-levels and check if any match the action supplied
            if (context.getActionPrivileges() instanceof RoleBasedActionPrivileges roleBasedActionPrivileges) {
                Set<String> actions = roleBasedActionPrivileges.flattenedActionGroups().resolve(accessLevels);
                // a matcher to test against all patterns in `actions`
                WildcardMatcher matcher = WildcardMatcher.from(actions, true);
                if (matcher.test(action)) {
                    presponse.allowed = true;
                    log.debug("Resource {} is shared with user {}, granting access.", req.id(), user.getName());
                } else {
                    // TODO check why following addition doesn't reflect in the final response message and find an alternative
                    presponse.getMissingPrivileges().add(action);
                    log.debug("User {} has no {} privileges for {}", user.getName(), action, req.id());
                }
                latch.countDown();
            } else {
                // we don't yet support Plugins to access resources
                presponse.allowed = false;
                log.debug(
                    "Plugin access to resources is currently not supported. Plugin {} is not authorized to access resource {}.",
                    user.getName(),
                    req.id()
                );
                latch.countDown();
            }
            shouldMarkAsComplete.set(true);

        }, e -> {
            presponse.allowed = false;
            log.debug("Something went wrong while evaluating resource {}. Marking request as unauthorized.", req.id());
            shouldMarkAsComplete.set(true);
            latch.countDown();
        }));
        try {
            latch.await();
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }

        return shouldMarkAsComplete.get() ? presponse.markComplete() : presponse;
    }
}
