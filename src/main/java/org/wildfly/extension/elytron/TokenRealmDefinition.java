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
import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.ResourceDefinition;
import org.jboss.as.controller.RestartParentWriteAttributeHandler;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.as.controller.SimpleResourceDefinition;
import org.jboss.as.controller.registry.AttributeAccess;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.OperationEntry;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.jboss.msc.service.StartException;
import org.wildfly.extension.elytron._private.ElytronSubsystemMessages;
import org.wildfly.security.auth.realm.token.TokenSecurityRealm;
import org.wildfly.security.auth.realm.token.validator.JwtValidator;
import org.wildfly.security.auth.server.SecurityRealm;

import static org.wildfly.extension.elytron.Capabilities.MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY;
import static org.wildfly.extension.elytron.Capabilities.SECURITY_REALM_RUNTIME_CAPABILITY;


/**
 * A {@link ResourceDefinition} for a {@link SecurityRealm} capable of validating and extracting identities from security tokens.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class TokenRealmDefinition extends SimpleResourceDefinition {

    static final SimpleAttributeDefinition PRINCIPAL_CLAIM = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PRINCIPAL_CLAIM, ModelType.STRING, true)
                                                                     .setDefaultValue(new ModelNode("sub"))
                                                                     .setAllowExpression(false)
                                                                     .setMinSize(1)
                                                                     .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                                                                     .build();

    static class JwtValidatorAttributes {

        static final SimpleAttributeDefinition ISSUER = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.ISSUER, ModelType.STRING, false)
                                                                .setAllowExpression(false)
                                                                .setMinSize(1)
                                                                .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                                                                .build();

        static final SimpleAttributeDefinition AUDIENCE = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.AUDIENCE, ModelType.STRING, false)
                                                                  .setAllowExpression(false)
                                                                  .setMinSize(1)
                                                                  .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                                                                  .build();

        static final SimpleAttributeDefinition PUBLIC_KEY = new SimpleAttributeDefinitionBuilder(ElytronDescriptionConstants.PUBLIC_KEY, ModelType.STRING, false)
                                                                    .setAllowExpression(false)
                                                                    .setMinSize(1)
                                                                    .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                                                                    .build();

        static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[]{ISSUER, AUDIENCE, PUBLIC_KEY};

        static final ObjectTypeAttributeDefinition JWT_VALIDATOR = new ObjectTypeAttributeDefinition.Builder(ElytronDescriptionConstants.JWT, ISSUER, AUDIENCE, PUBLIC_KEY)
                                                                           .setAllowNull(false)
                                                                           .setFlags(AttributeAccess.Flag.RESTART_RESOURCE_SERVICES)
                                                                           .build();
    }

    private static final AttributeDefinition[] ATTRIBUTES = new AttributeDefinition[]{PRINCIPAL_CLAIM, JwtValidatorAttributes.JWT_VALIDATOR};

    private static final AbstractAddStepHandler ADD = new RealmAddHandler();
    private static final OperationStepHandler REMOVE = new TrivialCapabilityServiceRemoveHandler(ADD, MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY, SECURITY_REALM_RUNTIME_CAPABILITY);

    TokenRealmDefinition() {
        super(new Parameters(PathElement.pathElement(ElytronDescriptionConstants.TOKEN_REALM),
                                    ElytronExtension.getResourceDescriptionResolver(ElytronDescriptionConstants.TOKEN_REALM))
                      .setAddHandler(ADD)
                      .setRemoveHandler(REMOVE)
                      .setAddRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                      .setRemoveRestartLevel(OperationEntry.Flag.RESTART_RESOURCE_SERVICES)
                      .setCapabilities(MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY, SECURITY_REALM_RUNTIME_CAPABILITY));
    }

    @Override
    public void registerAttributes(ManagementResourceRegistration resourceRegistration) {
        OperationStepHandler handler = new WriteAttributeHandler();
        for (AttributeDefinition attr : ATTRIBUTES) {
            resourceRegistration.registerReadWriteAttribute(attr, null, handler);
        }
    }

    private static class RealmAddHandler extends BaseAddHandler {

        private RealmAddHandler() {
            super(SECURITY_REALM_RUNTIME_CAPABILITY, ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
                throws OperationFailedException {
            ServiceTarget serviceTarget = context.getServiceTarget();

            String address = context.getCurrentAddressValue();
            ServiceName mainServiceName = MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY.fromBaseCapability(address).getCapabilityServiceName();
            ServiceName aliasServiceName = SECURITY_REALM_RUNTIME_CAPABILITY.fromBaseCapability(address).getCapabilityServiceName();
            ModelNode principalClaimNode = PRINCIPAL_CLAIM.resolveModelAttribute(context, operation);
            ModelNode jwtValidatorNode = JwtValidatorAttributes.JWT_VALIDATOR.resolveModelAttribute(context, operation);
            TrivialService<SecurityRealm> service;

            if (jwtValidatorNode.isDefined()) {
                String issuer = ElytronExtension.asStringIfDefined(context, JwtValidatorAttributes.ISSUER, jwtValidatorNode);
                String audience = ElytronExtension.asStringIfDefined(context, JwtValidatorAttributes.AUDIENCE, jwtValidatorNode);
                String publicKey = ElytronExtension.asStringIfDefined(context, JwtValidatorAttributes.PUBLIC_KEY, jwtValidatorNode);
                service = new TrivialService<>(new TrivialService.ValueSupplier<SecurityRealm>() {
                    @Override
                    public SecurityRealm get() throws StartException {
                        return TokenSecurityRealm.builder()
                                       .principalClaimName(principalClaimNode.asString())
                                       .validator(JwtValidator.builder()
                                                          .issuer(issuer)
                                                          .audience(audience)
                                                          .publicKey(publicKey.getBytes()).build())
                                       .build();
                    }

                    @Override
                    public void dispose() {
                    }
                });
            } else {
                throw ElytronSubsystemMessages.ROOT_LOGGER.unexpectedPasswordType("token validator");
            }

            ServiceBuilder<SecurityRealm> serviceBuilder = serviceTarget.addService(mainServiceName, service)
                                                                   .addAliases(aliasServiceName);

            serviceBuilder.install();
        }

    }

    private static class WriteAttributeHandler extends RestartParentWriteAttributeHandler {

        WriteAttributeHandler() {
            super(ElytronDescriptionConstants.TOKEN_REALM, ATTRIBUTES);
        }

        @Override
        protected ServiceName getParentServiceName(PathAddress parentAddress) {
            final String name = parentAddress.getLastElement().getValue();
            return MODIFIABLE_SECURITY_REALM_RUNTIME_CAPABILITY.fromBaseCapability(name).getCapabilityServiceName();
        }
    }
}
