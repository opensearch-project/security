package com.amazon.opendistroforelasticsearch.security.privileges;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.ClusterInfoHolder;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;


public class PrivilegesEvaluatorFactory {

    public static Object getPrivilegesEvaluator(ClusterService clusterService, ThreadPool threadPool,
                                                ConfigurationRepository configurationRepository, IndexNameExpressionResolver resolver,
                                                AuditLog auditLog, Settings settings, PrivilegesInterceptor privilegesInterceptor, ClusterInfoHolder clusterInfoHolder,
                                                IndexResolverReplacer irr, boolean advancedModulesEnabled) throws ElasticsearchException,
            ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {

        Class<?> clazz = Class.forName(settings.get(ConfigConstants.OPENDISTRO_SECURITY_PRIVILEGES_EVALUATOR, OpenDistroPrivilegesEvaluator.class.getName()));
        Constructor<?> ctor = clazz.getConstructor(ClusterService.class, ThreadPool.class, ConfigurationRepository.class,
                IndexNameExpressionResolver.class, AuditLog.class, Settings.class,
                PrivilegesInterceptor.class, ClusterInfoHolder.class, IndexResolverReplacer.class, boolean.class);
        return ctor.newInstance(clusterService, threadPool, configurationRepository, resolver, auditLog, settings, privilegesInterceptor,
                clusterInfoHolder, irr, advancedModulesEnabled);

    }
}
