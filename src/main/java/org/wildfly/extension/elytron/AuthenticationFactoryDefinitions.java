/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.extension.elytron;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.ObjectListAttributeDefinition;
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.State;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismInformation;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.auth.server.SaslAuthenticationFactory;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.HttpServerScopes;
import org.wildfly.security.http.Scope;

import javax.net.ssl.SSLSession;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServerFactory;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;

import static org.jboss.as.controller.capability.RuntimeCapability.buildDynamicCapabilityName;
import static org.wildfly.extension.elytron.AvailableMechanismsRuntimeResource.wrap;
import static org.wildfly.extension.elytron.Capabilities.HTTP_AUTHENTICATION_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.HTTP_AUTHENTICATION_FACTORY_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.HTTP_SERVER_MECHANISM_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.NAME_REWRITER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.REALM_MAPPER_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_AUTHENTICATION_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_AUTHENTICATION_FACTORY_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SASL_SERVER_FACTORY_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_DOMAIN_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_FACTORY_CREDENTIAL_CAPABILITY;
import static org.wildfly.extension.elytron.ElytronExtension.asStringIfDefined;
import static org.wildfly.extension.elytron.ElytronExtension.getRequiredService;


/**
 * The {@link ResourceDefinition} instances for the authentication factory definitions.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class AuthenticationFactoryDefinitions {

    static final SimpleAttributeDefinition BASE_SECURITY_DOMAIN_REF = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SECURITY_DOMAIN, ModelType.STRING, false)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition HTTP_SERVER_MECHANISM_FACTORY = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.HTTP_SERVER_MECHANISM_FACTORY, ModelType.STRING, false)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setCapabilityReference(HTTP_SERVER_MECHANISM_FACTORY_CAPABILITY, HTTP_AUTHENTICATION_FACTORY_CAPABILITY, true)
            .build();

    static final SimpleAttributeDefinition SASL_SERVER_FACTORY = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SASL_SERVER_FACTORY, ModelType.STRING, false)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setCapabilityReference(SASL_SERVER_FACTORY_CAPABILITY, SASL_AUTHENTICATION_FACTORY_CAPABILITY, true)
            .build();

    static final SimpleAttributeDefinition MECHANISM_NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.MECHANISM_NAME, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setAttributeGroup(ElytronDescriptionConstants.SELECTION_CRITERIA)
            .build();

    static final SimpleAttributeDefinition HOST_NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.HOST_NAME, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setAttributeGroup(ElytronDescriptionConstants.SELECTION_CRITERIA)
            .build();

    static final SimpleAttributeDefinition PROTOCOL = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PROTOCOL, ModelType.STRING, true)
            .setAllowExpression(true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .setAttributeGroup(ElytronDescriptionConstants.SELECTION_CRITERIA)
            .build();

    static final SimpleAttributeDefinition BASE_CREDENTIAL_SECURITY_FACTORY = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.CREDENTIAL_SECURITY_FACTORY, ModelType.STRING, true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition BASE_PRE_REALM_NAME_REWRITER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PRE_REALM_NAME_REWRITER, ModelType.STRING, true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition BASE_POST_REALM_NAME_REWRITER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.POST_REALM_NAME_REWRITER, ModelType.STRING, true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition BASE_FINAL_NAME_REWRITER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.FINAL_NAME_REWRITER, ModelType.STRING, true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition BASE_REALM_MAPPER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REALM_MAPPER, ModelType.STRING, true)
            .setMinSize(1)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition REALM_NAME = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.REALM_NAME, ModelType.STRING, false)
            .setMinSize(1)
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    static final SimpleAttributeDefinition SINGLE_SIGN_ONE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.SINGLE_SIGN_ON, ModelType.BOOLEAN, true)
            .setDefaultValue(new ModelNode(false))
            .setMinSize(1)
            .setAllowExpression(true)
            .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
            .build();

    private static AttributeDefinition getMechanismConfiguration(String forCapability) {
        SimpleAttributeDefinition preRealmNameRewriterAttribute = new SimpleAttributeDefinitionBuilder(BASE_PRE_REALM_NAME_REWRITER)
                .setCapabilityReference(NAME_REWRITER_CAPABILITY, forCapability, true)
                .build();
        SimpleAttributeDefinition postRealmNameRewriterAttribute = new SimpleAttributeDefinitionBuilder(BASE_POST_REALM_NAME_REWRITER)
                .setCapabilityReference(NAME_REWRITER_CAPABILITY, forCapability, true)
                .build();
        SimpleAttributeDefinition finalNameRewriterAttribute = new SimpleAttributeDefinitionBuilder(BASE_FINAL_NAME_REWRITER)
                .setCapabilityReference(NAME_REWRITER_CAPABILITY, forCapability, true)
                .build();
        SimpleAttributeDefinition realmMapperAttribute = new SimpleAttributeDefinitionBuilder(BASE_REALM_MAPPER)
                .setCapabilityReference(REALM_MAPPER_CAPABILITY, forCapability, true)
                .build();

        ObjectTypeAttributeDefinition mechanismRealmConfiguration = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_REALM_CONFIGURATION, REALM_NAME, preRealmNameRewriterAttribute, postRealmNameRewriterAttribute, finalNameRewriterAttribute, realmMapperAttribute)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        ObjectListAttributeDefinition mechanismRealmConfigurations = new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_REALM_CONFIGURATIONS, mechanismRealmConfiguration)
                .setAllowNull(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        SimpleAttributeDefinition credentialSecurityFactoryAttribute = new SimpleAttributeDefinitionBuilder(BASE_CREDENTIAL_SECURITY_FACTORY)
                .setCapabilityReference(SECURITY_FACTORY_CREDENTIAL_CAPABILITY, forCapability, true)
                .build();

        ObjectTypeAttributeDefinition mechanismConfiguration = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_CONFIGURATION, MECHANISM_NAME, HOST_NAME, PROTOCOL,
                preRealmNameRewriterAttribute, postRealmNameRewriterAttribute, finalNameRewriterAttribute, realmMapperAttribute, mechanismRealmConfigurations, credentialSecurityFactoryAttribute)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();

        return new ObjectListAttributeDefinition.Builder(ElytronDescriptionConstants.MECHANISM_CONFIGURATIONS, mechanismConfiguration)
                .setAllowNull(true)
                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                .build();
    }

    static List<ResolvedMechanismConfiguration> getResolvedMechanismConfiguration(AttributeDefinition mechanismConfigurationAttribute, ServiceBuilder<?> serviceBuilder,
            OperationContext context, ModelNode model) throws OperationFailedException {
        ModelNode mechanismConfiguration = mechanismConfigurationAttribute.resolveModelAttribute(context, model);
        if (mechanismConfiguration.isDefined() == false) {
            return Collections.emptyList();
        }
        List<ModelNode> mechanismConfigurations = mechanismConfiguration.asList();
        List<ResolvedMechanismConfiguration> resolvedMechanismConfigurations = new ArrayList<>(mechanismConfigurations.size());
        for (ModelNode currentMechanismConfiguration : mechanismConfigurations) {
            final String mechanismName = asStringIfDefined(context, MECHANISM_NAME, currentMechanismConfiguration);
            final String hostName = asStringIfDefined(context, HOST_NAME, currentMechanismConfiguration);
            final String protocol = asStringIfDefined(context, PROTOCOL, currentMechanismConfiguration);

            Predicate<MechanismInformation> selectionPredicate = null;
            if (mechanismName != null) {
                selectionPredicate = i -> mechanismName.equals(i.getMechanismName());
            }
            if (hostName != null) {
                Predicate<MechanismInformation> hostPredicate = i -> hostName.equals(i.getHostName());
                selectionPredicate = selectionPredicate != null ? selectionPredicate.and(hostPredicate) : hostPredicate;
            }
            if (protocol != null) {
                Predicate<MechanismInformation> protocolPredicate = i -> protocol.equals(i.getProtocol());
                selectionPredicate = selectionPredicate != null ? selectionPredicate.and(protocolPredicate) : protocolPredicate;
            }

            if (selectionPredicate == null) {
                selectionPredicate = i -> true;
            }

            ResolvedMechanismConfiguration resolvedMechanismConfiguration = new ResolvedMechanismConfiguration(selectionPredicate);

            injectNameRewriter(BASE_PRE_REALM_NAME_REWRITER, serviceBuilder, context, currentMechanismConfiguration, resolvedMechanismConfiguration.preRealmNameRewriter);
            injectNameRewriter(BASE_POST_REALM_NAME_REWRITER, serviceBuilder, context, currentMechanismConfiguration, resolvedMechanismConfiguration.postRealmNameRewriter);
            injectNameRewriter(BASE_FINAL_NAME_REWRITER, serviceBuilder, context, currentMechanismConfiguration, resolvedMechanismConfiguration.finalNameRewriter);
            injectRealmMapper(BASE_REALM_MAPPER, serviceBuilder, context, currentMechanismConfiguration, resolvedMechanismConfiguration.realmMapper);
            injectSecurityFactory(BASE_CREDENTIAL_SECURITY_FACTORY, serviceBuilder, context, currentMechanismConfiguration, resolvedMechanismConfiguration.securityFactory);

            if (currentMechanismConfiguration.hasDefined(ElytronDescriptionConstants.MECHANISM_REALM_CONFIGURATIONS)) {
                for (ModelNode currentMechanismRealm : currentMechanismConfiguration.require(ElytronDescriptionConstants.MECHANISM_REALM_CONFIGURATIONS).asList()) {
                    String realmName = REALM_NAME.resolveModelAttribute(context, currentMechanismRealm).asString();
                    ResolvedMechanismRealmConfiguration resolvedMechanismRealmConfiguration = new ResolvedMechanismRealmConfiguration();
                    injectNameRewriter(BASE_PRE_REALM_NAME_REWRITER, serviceBuilder, context, currentMechanismRealm, resolvedMechanismRealmConfiguration.preRealmNameRewriter);
                    injectNameRewriter(BASE_POST_REALM_NAME_REWRITER, serviceBuilder, context, currentMechanismRealm, resolvedMechanismRealmConfiguration.postRealmNameRewriter);
                    injectNameRewriter(BASE_FINAL_NAME_REWRITER, serviceBuilder, context, currentMechanismRealm, resolvedMechanismRealmConfiguration.finalNameRewriter);
                    injectRealmMapper(BASE_REALM_MAPPER, serviceBuilder, context, currentMechanismRealm, resolvedMechanismRealmConfiguration.realmMapper);
                    resolvedMechanismConfiguration.mechanismRealms.put(realmName, resolvedMechanismRealmConfiguration);
                }
            }

            resolvedMechanismConfigurations.add(resolvedMechanismConfiguration);
        }

        return resolvedMechanismConfigurations;
    }

    static void buildMechanismConfiguration(List<ResolvedMechanismConfiguration> resolvedMechanismConfigurations, MechanismAuthenticationFactory.Builder factoryBuilder) {
        ArrayList<MechanismConfigurationSelector> mechanismConfigurationSelectors = new ArrayList<>(resolvedMechanismConfigurations.size());
        for (ResolvedMechanismConfiguration resolvedMechanismConfiguration : resolvedMechanismConfigurations) {
            MechanismConfiguration.Builder builder = MechanismConfiguration.builder();

            setNameRewriter(resolvedMechanismConfiguration.preRealmNameRewriter, builder::setPreRealmRewriter);
            setNameRewriter(resolvedMechanismConfiguration.postRealmNameRewriter, builder::setPostRealmRewriter);
            setNameRewriter(resolvedMechanismConfiguration.finalNameRewriter, builder::setFinalRewriter);
            setRealmMapper(resolvedMechanismConfiguration.realmMapper, builder::setRealmMapper);
            setSecurityFactory(resolvedMechanismConfiguration.securityFactory, builder::setServerCredential);

            for (Entry<String, ResolvedMechanismRealmConfiguration> currentMechRealmEntry : resolvedMechanismConfiguration.mechanismRealms.entrySet()) {
                MechanismRealmConfiguration.Builder mechRealmBuilder = MechanismRealmConfiguration.builder();
                mechRealmBuilder.setRealmName(currentMechRealmEntry.getKey());
                ResolvedMechanismRealmConfiguration resolvedMechanismRealmConfiguration = currentMechRealmEntry.getValue();

                setNameRewriter(resolvedMechanismRealmConfiguration.preRealmNameRewriter, mechRealmBuilder::setPreRealmRewriter);
                setNameRewriter(resolvedMechanismRealmConfiguration.postRealmNameRewriter, mechRealmBuilder::setPostRealmRewriter);
                setNameRewriter(resolvedMechanismRealmConfiguration.finalNameRewriter, mechRealmBuilder::setFinalRewriter);
                setRealmMapper(resolvedMechanismRealmConfiguration.realmMapper, mechRealmBuilder::setRealmMapper);

                builder.addMechanismRealm(mechRealmBuilder.build());
            }

            mechanismConfigurationSelectors.add(MechanismConfigurationSelector.predicateSelector(resolvedMechanismConfiguration.selectionPredicate, builder.build()));
        }

        factoryBuilder.setMechanismConfigurationSelector(MechanismConfigurationSelector.aggregate(mechanismConfigurationSelectors.toArray(new MechanismConfigurationSelector[mechanismConfigurationSelectors.size()])));
    }

    private static void setNameRewriter(InjectedValue<NameRewriter> injectedValue, Consumer<NameRewriter> nameRewriterConsumer) {
        NameRewriter nameRewriter = injectedValue.getOptionalValue();
        if (nameRewriter != null) {
            nameRewriterConsumer.accept(nameRewriter);
        }
    }

    private static void injectNameRewriter(SimpleAttributeDefinition nameRewriterAttribute, ServiceBuilder<?> serviceBuilder, OperationContext context, ModelNode model, Injector<NameRewriter> preRealmNameRewriter) throws OperationFailedException {
        String nameRewriter = asStringIfDefined(context, nameRewriterAttribute, model);
        if (nameRewriter != null) {
            serviceBuilder.addDependency(context.getCapabilityServiceName(
                    buildDynamicCapabilityName(NAME_REWRITER_CAPABILITY, nameRewriter), NameRewriter.class),
                    NameRewriter.class, preRealmNameRewriter);
        }
    }

    private static void setSecurityFactory(InjectedValue<SecurityFactory> injectedValue, Consumer<SecurityFactory> securityFactoryConsumer) {
        SecurityFactory securityFactory = injectedValue.getOptionalValue();
        if (securityFactory != null) {
            securityFactoryConsumer.accept(securityFactory);
        }
    }

    private static void injectSecurityFactory(SimpleAttributeDefinition securityFactoryAttribute, ServiceBuilder<?> serviceBuilder, OperationContext context, ModelNode model, Injector<SecurityFactory> securityFactoryInjector) throws OperationFailedException {
        String securityFactory = asStringIfDefined(context, securityFactoryAttribute, model);
        if (securityFactory != null) {
            serviceBuilder.addDependency(context.getCapabilityServiceName(
                    buildDynamicCapabilityName(SECURITY_FACTORY_CREDENTIAL_CAPABILITY, securityFactory), SecurityFactory.class),
                    SecurityFactory.class, securityFactoryInjector);
        }
    }

    private static void setRealmMapper(InjectedValue<RealmMapper> injectedValue, Consumer<RealmMapper> realmMapperConsumer) {
        RealmMapper realmMapper = injectedValue.getOptionalValue();
        if (realmMapper != null) {
            realmMapperConsumer.accept(realmMapper);
        }
    }

    private static void injectRealmMapper(SimpleAttributeDefinition realmMapperAttribute, ServiceBuilder<?> serviceBuilder, OperationContext context, ModelNode model, Injector<RealmMapper> realmMapperInjector) throws OperationFailedException {
        String realmMapper = asStringIfDefined(context, realmMapperAttribute, model);
        if (realmMapper != null) {
            serviceBuilder.addDependency(context.getCapabilityServiceName(
                    buildDynamicCapabilityName(REALM_MAPPER_CAPABILITY, realmMapper), RealmMapper.class),
                    RealmMapper.class, realmMapperInjector);
        }
    }

    static ResourceDefinition getHttpAuthenticationFactory() {

        SimpleAttributeDefinition securityDomainAttribute = new SimpleAttributeDefinitionBuilder(BASE_SECURITY_DOMAIN_REF)
                .setCapabilityReference(SECURITY_DOMAIN_CAPABILITY, HTTP_AUTHENTICATION_FACTORY_CAPABILITY, true)
                .build();

        AttributeDefinition mechanismConfigurationAttribute = getMechanismConfiguration(HTTP_AUTHENTICATION_FACTORY_CAPABILITY);

        AttributeDefinition[] attributes = new AttributeDefinition[] { securityDomainAttribute, HTTP_SERVER_MECHANISM_FACTORY, SINGLE_SIGN_ONE, mechanismConfigurationAttribute };
        AbstractAddStepHandler add = new TrivialAddHandler<HttpAuthenticationFactory>(HttpAuthenticationFactory.class, attributes, HTTP_AUTHENTICATION_FACTORY_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<HttpAuthenticationFactory> getValueSupplier(
                    ServiceBuilder<HttpAuthenticationFactory> serviceBuilder, ServiceTarget serviceTarget, ServiceName mainName, String address, OperationContext context, ModelNode model)
                    throws OperationFailedException {

                final InjectedValue<SecurityDomain> securityDomainInjector = new InjectedValue<SecurityDomain>();
                final InjectedValue<HttpServerAuthenticationMechanismFactory> mechanismFactoryInjector = new InjectedValue<HttpServerAuthenticationMechanismFactory>();
                final InjectedValue<IdentityCacheFactory> identityCacheInjector = new InjectedValue<>();

                String securityDomain = securityDomainAttribute.resolveModelAttribute(context, model).asString();
                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(SECURITY_DOMAIN_CAPABILITY, securityDomain), SecurityDomain.class),
                        SecurityDomain.class, securityDomainInjector);

                String httpServerFactory = HTTP_SERVER_MECHANISM_FACTORY.resolveModelAttribute(context, model).asString();
                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(HTTP_SERVER_MECHANISM_FACTORY_CAPABILITY, httpServerFactory), HttpServerAuthenticationMechanismFactory.class),
                        HttpServerAuthenticationMechanismFactory.class, mechanismFactoryInjector);

                boolean singleSignOn = SINGLE_SIGN_ONE.resolveModelAttribute(context, model).asBoolean();

                if (singleSignOn) {
                    Iterator<IdentityCacheFactoryServiceBuilder> iterator = ServiceLoader.load(IdentityCacheFactoryServiceBuilder.class, AuthenticationFactoryDefinitions.class.getClassLoader()).iterator();

                    if (iterator.hasNext()) {
                        IdentityCacheFactoryServiceBuilder clusteredIdentityCache = iterator.next();
                        ServiceName name = mainName.append("identity");
                        clusteredIdentityCache.build(serviceTarget, name, address)
                                .setInitialMode(ServiceController.Mode.ON_DEMAND)
                                .install();
                        serviceBuilder.addDependency(name, IdentityCacheFactory.class, identityCacheInjector);
                    }
                }

                final List<ResolvedMechanismConfiguration> resolvedMechanismConfigurations = getResolvedMechanismConfiguration(mechanismConfigurationAttribute, serviceBuilder, context, model);

                return () -> {
                    HttpServerAuthenticationMechanismFactory injectedHttpServerFactory = mechanismFactoryInjector.getValue();
                    IdentityCacheFactory identityCacheFactory = identityCacheInjector.getOptionalValue();
                    HttpServerAuthenticationMechanismFactory finalHttpServerFactory;

                    if (identityCacheFactory == null) {
                        finalHttpServerFactory = injectedHttpServerFactory;
                    } else {
                        finalHttpServerFactory = createClusteredServerMechanismFactory(injectedHttpServerFactory, identityCacheFactory);
                    }

                    HttpAuthenticationFactory.Builder builder = HttpAuthenticationFactory.builder()
                            .setSecurityDomain(securityDomainInjector.getValue())
                            .setFactory(finalHttpServerFactory);

                    buildMechanismConfiguration(resolvedMechanismConfigurations, builder);

                    return builder.build();
                };
            }

            private HttpServerAuthenticationMechanismFactory createClusteredServerMechanismFactory(final HttpServerAuthenticationMechanismFactory injectedHttpServerFactory, final IdentityCacheFactory identityCacheFactory) {
                return new HttpServerAuthenticationMechanismFactory() {
                    @Override
                    public String[] getMechanismNames(Map<String, ?> properties) {
                        return injectedHttpServerFactory.getMechanismNames(properties);
                    }

                    @Override
                    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) throws HttpAuthenticationException {
                        return new HttpServerAuthenticationMechanism() {
                            private HttpServerAuthenticationMechanism delegate;

                            @Override
                            public String getMechanismName() {
                                return mechanismName;
                            }

                            @Override
                            public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
                                IdentityCache identityCache = identityCacheFactory.create(() -> request);
                                HttpServerRequest wrapper = createHttpServerRequest(request, identityCache);
                                getDelegate(identityCache).evaluateRequest(wrapper);
                            }

                            private HttpServerAuthenticationMechanism getDelegate(IdentityCache identityCache) throws HttpAuthenticationException {
                                return injectedHttpServerFactory.createAuthenticationMechanism(mechanismName, properties, createCallbackHandler(callbackHandler, identityCache));
                            }
                        };
                    }

                    private CallbackHandler createCallbackHandler(CallbackHandler callbackHandler, IdentityCache identityCache) {
                        return callbacks -> {
                            CachedIdentityAuthorizeCallback delegate = null;
                            CachedIdentityAuthorizeCallback authorizeCallback = null;
                            for (int i = 0; i < callbacks.length; i++) {
                                Callback current = callbacks[i];

                                if (current instanceof CachedIdentityAuthorizeCallback) {
                                    delegate = (CachedIdentityAuthorizeCallback) current;
                                    Principal principal = delegate.getAuthorizationPrincipal();
                                    if (principal != null) {
                                        authorizeCallback = new CachedIdentityAuthorizeCallback(principal, identityCache);
                                    } else {
                                        authorizeCallback = new CachedIdentityAuthorizeCallback(identityCache);
                                    }
                                    callbacks[i] = authorizeCallback;
                                }
                            }
                            callbackHandler.handle(callbacks);
                            if (authorizeCallback != null) {
                                delegate.setAuthorized(authorizeCallback.getIdentity());
                            }
                        };
                    }

                    private HttpServerRequest createHttpServerRequest(final HttpServerRequest request, IdentityCache identityCache) {
                        HttpServerRequest httpServerRequest = new HttpServerRequest() {
                            @Override
                            public List<String> getRequestHeaderValues(String headerName) {
                                return request.getRequestHeaderValues(headerName);
                            }

                            @Override
                            public String getFirstRequestHeaderValue(String headerName) {
                                return request.getFirstRequestHeaderValue(headerName);
                            }

                            @Override
                            public SSLSession getSSLSession() {
                                return request.getSSLSession();
                            }

                            @Override
                            public void noAuthenticationInProgress(HttpServerMechanismsResponder responder) {
                                request.noAuthenticationInProgress(new HttpServerMechanismsResponder() {
                                    @Override
                                    public void sendResponse(HttpServerResponse response) throws HttpAuthenticationException {
                                        response.setResponseCookie(new HttpServerCookie() {
                                            @Override
                                            public String getName() {
                                                return "ELY_IDENTITY";
                                            }

                                            @Override
                                            public String getValue() {
                                                return null;
                                            }

                                            @Override
                                            public String getDomain() {
                                                return getRequestURI().getHost();
                                            }

                                            @Override
                                            public int getMaxAge() {
                                                return 0;
                                            }

                                            @Override
                                            public String getPath() {
                                                return "/";
                                            }

                                            @Override
                                            public boolean isSecure() {
                                                return false;
                                            }

                                            @Override
                                            public int getVersion() {
                                                return 0;
                                            }

                                            @Override
                                            public boolean isHttpOnly() {
                                                return true;
                                            }
                                        });

                                        if (responder != null) {
                                            responder.sendResponse(response);
                                        }
                                    }
                                });
                            }

                            @Override
                            public void authenticationInProgress(HttpServerMechanismsResponder responder) {
                                request.authenticationInProgress(new HttpServerMechanismsResponder() {
                                    @Override
                                    public void sendResponse(HttpServerResponse response) throws HttpAuthenticationException {
                                        response.setResponseCookie(new HttpServerCookie() {
                                            @Override
                                            public String getName() {
                                                return "ELY_IDENTITY";
                                            }

                                            @Override
                                            public String getValue() {
                                                return null;
                                            }

                                            @Override
                                            public String getDomain() {
                                                return getRequestURI().getHost();
                                            }

                                            @Override
                                            public int getMaxAge() {
                                                return 0;
                                            }

                                            @Override
                                            public String getPath() {
                                                return "/";
                                            }

                                            @Override
                                            public boolean isSecure() {
                                                return false;
                                            }

                                            @Override
                                            public int getVersion() {
                                                return 0;
                                            }

                                            @Override
                                            public boolean isHttpOnly() {
                                                return true;
                                            }
                                        });

                                        if (responder != null) {
                                            responder.sendResponse(response);
                                        }
                                    }
                                });
                            }

                            @Override
                            public void authenticationComplete(HttpServerMechanismsResponder responder) {
                                CachedIdentity identity = identityCache.get();

                                request.authenticationComplete(response -> {
                                    if (identity != null) {
                                        response.setResponseCookie(new HttpServerCookie() {
                                            @Override
                                            public String getName() {
                                                return "ELY_IDENTITY";
                                            }

                                            @Override
                                            public String getValue() {
                                                return identity.getId();
                                            }

                                            @Override
                                            public String getDomain() {
                                                return getRequestURI().getHost();
                                            }

                                            @Override
                                            public int getMaxAge() {
                                                return -1;
                                            }

                                            @Override
                                            public String getPath() {
                                                return "/";
                                            }

                                            @Override
                                            public boolean isSecure() {
                                                return false;
                                            }

                                            @Override
                                            public int getVersion() {
                                                return 0;
                                            }

                                            @Override
                                            public boolean isHttpOnly() {
                                                return true;
                                            }
                                        });
                                    }
                                    if (responder != null) {
                                        responder.sendResponse(response);
                                    }
                                });
                            }

                            @Override
                            public void authenticationFailed(String message, HttpServerMechanismsResponder responder) {
                                request.authenticationFailed(message, responder);
                                request.authenticationFailed(message, response -> {
                                    response.setResponseCookie(new HttpServerCookie() {
                                        @Override
                                        public String getName() {
                                            return "ELY_IDENTITY";
                                        }

                                        @Override
                                        public String getValue() {
                                            return null;
                                        }

                                        @Override
                                        public String getDomain() {
                                            return getRequestURI().getHost();
                                        }

                                        @Override
                                        public int getMaxAge() {
                                            return 0;
                                        }

                                        @Override
                                        public String getPath() {
                                            return "/";
                                        }

                                        @Override
                                        public boolean isSecure() {
                                            return false;
                                        }

                                        @Override
                                        public int getVersion() {
                                            return 0;
                                        }

                                        @Override
                                        public boolean isHttpOnly() {
                                            return true;
                                        }
                                    });

                                    if (responder != null) {
                                        responder.sendResponse(response);
                                    }
                                });
                            }

                            @Override
                            public void badRequest(HttpAuthenticationException failure, HttpServerMechanismsResponder responder) {
                                request.badRequest(failure, responder);
                            }

                            @Override
                            public String getRequestMethod() {
                                return request.getRequestMethod();
                            }

                            @Override
                            public URI getRequestURI() {
                                return request.getRequestURI();
                            }

                            @Override
                            public Map<String, List<String>> getParameters() {
                                return request.getParameters();
                            }

                            @Override
                            public Set<String> getParameterNames() {
                                return request.getParameterNames();
                            }

                            @Override
                            public List<String> getParameterValues(String name) {
                                return request.getParameterValues(name);
                            }

                            @Override
                            public String getFirstParameterValue(String name) {
                                return request.getFirstParameterValue(name);
                            }

                            @Override
                            public List<HttpServerCookie> getCookies() {
                                return request.getCookies();
                            }

                            @Override
                            public InputStream getInputStream() {
                                return request.getInputStream();
                            }

                            @Override
                            public InetSocketAddress getSourceAddress() {
                                return request.getSourceAddress();
                            }

                            @Override
                            public boolean suspendRequest() {
                                return request.suspendRequest();
                            }

                            @Override
                            public boolean resumeRequest() {
                                return request.resumeRequest();
                            }

                            @Override
                            public HttpScope getScope(Scope scope) {
                                return request.getScope(scope);
                            }

                            @Override
                            public Collection<String> getScopeIds(Scope scope) {
                                return request.getScopeIds(scope);
                            }

                            @Override
                            public HttpScope getScope(Scope scope, String id) {
                                return request.getScope(scope, id);
                            }
                        };

                        HttpScope scope = request.getScope(Scope.SESSION);

                        if (scope != null) {
                            Consumer<HttpServerScopes> sessionNotificationHandler = httpServerScopes -> identityCache.remove();
                            scope.registerForNotification(sessionNotificationHandler);
                        }

                        return httpServerRequest;
                    }
                };
            }
        };

        return wrap(new TrivialResourceDefinition(ElytronDescriptionConstants.HTTP_AUTHENTICATION_FACTORY,
                add, attributes, HTTP_AUTHENTICATION_FACTORY_RUNTIME_CAPABILITY), AuthenticationFactoryDefinitions::getAvailableHttpMechanisms);
    }

    private static String[] getAvailableHttpMechanisms(OperationContext context) {
        RuntimeCapability<Void> runtimeCapability = HTTP_AUTHENTICATION_FACTORY_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
        ServiceName securityDomainHttpConfigurationName = runtimeCapability.getCapabilityServiceName(HttpAuthenticationFactory.class);

        ServiceController<HttpAuthenticationFactory> serviceContainer = getRequiredService(context.getServiceRegistry(false), securityDomainHttpConfigurationName, HttpAuthenticationFactory.class);
        if (serviceContainer.getState() != State.UP) {
            return null;
        }

        Collection<String> mechanismNames = serviceContainer.getValue().getMechanismNames();
        return  mechanismNames.toArray(new String[mechanismNames.size()]);
    }

    static ResourceDefinition getSaslAuthenticationFactory() {
        SimpleAttributeDefinition securityDomainAttribute = new SimpleAttributeDefinitionBuilder(BASE_SECURITY_DOMAIN_REF)
                .setCapabilityReference(SECURITY_DOMAIN_CAPABILITY, SASL_AUTHENTICATION_FACTORY_CAPABILITY, true)
                .build();

        AttributeDefinition mechanismConfigurationAttribute = getMechanismConfiguration(SASL_AUTHENTICATION_FACTORY_CAPABILITY);

        AttributeDefinition[] attributes = new AttributeDefinition[] { securityDomainAttribute, SASL_SERVER_FACTORY, mechanismConfigurationAttribute };

        AbstractAddStepHandler add = new TrivialAddHandler<SaslAuthenticationFactory>(SaslAuthenticationFactory.class, attributes, SASL_AUTHENTICATION_FACTORY_RUNTIME_CAPABILITY) {

            @Override
            protected ValueSupplier<SaslAuthenticationFactory> getValueSupplier(
                    ServiceBuilder<SaslAuthenticationFactory> serviceBuilder, ServiceTarget serviceTarget, ServiceName mainName, String address, OperationContext context, ModelNode model)
                    throws OperationFailedException {

                String securityDomain = securityDomainAttribute.resolveModelAttribute(context, model).asString();
                String saslServerFactory = SASL_SERVER_FACTORY.resolveModelAttribute(context, model).asString();

                final InjectedValue<SecurityDomain> securityDomainInjector = new InjectedValue<SecurityDomain>();
                final InjectedValue<SaslServerFactory> saslServerFactoryInjector = new InjectedValue<SaslServerFactory>();

                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(SECURITY_DOMAIN_CAPABILITY, securityDomain), SecurityDomain.class),
                        SecurityDomain.class, securityDomainInjector);

                serviceBuilder.addDependency(context.getCapabilityServiceName(
                        buildDynamicCapabilityName(SASL_SERVER_FACTORY_CAPABILITY, saslServerFactory), SaslServerFactory.class),
                        SaslServerFactory.class, saslServerFactoryInjector);

                final List<ResolvedMechanismConfiguration> resolvedMechanismConfigurations = getResolvedMechanismConfiguration(mechanismConfigurationAttribute, serviceBuilder, context, model);

                return () -> {
                    SaslServerFactory injectedSaslServerFactory = saslServerFactoryInjector.getValue();

                    SaslAuthenticationFactory.Builder builder = SaslAuthenticationFactory.builder()
                            .setSecurityDomain(securityDomainInjector.getValue())
                            .setFactory(injectedSaslServerFactory);

                    buildMechanismConfiguration(resolvedMechanismConfigurations, builder);

                    return builder.build();
                };
            }
        };

        return wrap(new TrivialResourceDefinition(ElytronDescriptionConstants.SASL_AUTHENTICATION_FACTORY,
                add, attributes, SASL_AUTHENTICATION_FACTORY_RUNTIME_CAPABILITY), AuthenticationFactoryDefinitions::getAvailableSaslMechanisms);
    }

    private static String[] getAvailableSaslMechanisms(OperationContext context) {
        RuntimeCapability<Void> runtimeCapability = SASL_AUTHENTICATION_FACTORY_RUNTIME_CAPABILITY.fromBaseCapability(context.getCurrentAddressValue());
        ServiceName securityDomainSaslConfigurationName = runtimeCapability.getCapabilityServiceName(SaslAuthenticationFactory.class);

        ServiceController<SaslAuthenticationFactory> serviceContainer = getRequiredService(context.getServiceRegistry(false), securityDomainSaslConfigurationName, SaslAuthenticationFactory.class);
        if (serviceContainer.getState() != State.UP) {
            return null;
        }

        Collection<String> mechanismNames = serviceContainer.getValue().getMechanismNames();
        return  mechanismNames.toArray(new String[mechanismNames.size()]);
    }

    private static class ResolvedMechanismRealmConfiguration {
        final InjectedValue<NameRewriter> preRealmNameRewriter = new InjectedValue<>();
        final InjectedValue<NameRewriter> postRealmNameRewriter = new InjectedValue<>();
        final InjectedValue<NameRewriter> finalNameRewriter = new InjectedValue<>();
        final InjectedValue<RealmMapper> realmMapper = new InjectedValue<>();
    }

    private static class ResolvedMechanismConfiguration extends ResolvedMechanismRealmConfiguration {
        final Predicate<MechanismInformation> selectionPredicate;
        final Map<String, ResolvedMechanismRealmConfiguration> mechanismRealms = new HashMap<>();
        final InjectedValue<SecurityFactory> securityFactory = new InjectedValue<>();

        ResolvedMechanismConfiguration(Predicate<MechanismInformation> selectionPredicate) {
            this.selectionPredicate = selectionPredicate;

        }

    }

}
