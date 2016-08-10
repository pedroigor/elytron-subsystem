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

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.extension.elytron.ElytronDefinition.commonDependencies;

import java.util.Arrays;
import java.util.HashSet;

import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.OperationStepHandler;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.registry.Resource;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.wildfly.extension.elytron.TrivialService.ValueSupplier;

/**
 * A trivial {@link OperationStepHandler} for adding a {@link Service} for a resource.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
abstract class TrivialAddHandler<T> extends BaseAddHandler {

    private final RuntimeCapability<?>[] runtimeCapabilities;
    private final Mode initialMode;

    TrivialAddHandler(Class<T> serviceType, AttributeDefinition[] attributes, RuntimeCapability<?> ... runtimeCapabilities) {
        this(serviceType, Mode.ACTIVE, attributes, runtimeCapabilities);
    }

    TrivialAddHandler(Class<T> serviceType, Mode initialMode, AttributeDefinition[] attributes, RuntimeCapability<?> ... runtimeCapabilities) {
        super( new HashSet<RuntimeCapability>( Arrays.asList(checkNotNullParam("runtimeCapabilities", runtimeCapabilities))), attributes);
        this.runtimeCapabilities = runtimeCapabilities;
        checkNotNullParam("serviceType", serviceType);
        this.initialMode = checkNotNullParam("initialMode", initialMode);
    }

    @Override
    protected final void performRuntime(OperationContext context, ModelNode operation, Resource resource)
            throws OperationFailedException {
        String address = context.getCurrentAddressValue();
        ServiceName mainName = runtimeCapabilities[0].fromBaseCapability(address).getCapabilityServiceName();

        ServiceTarget serviceTarget = context.getServiceTarget();
        TrivialService<T> trivialService = new TrivialService<T>();

        ServiceBuilder<T> serviceBuilder = serviceTarget.addService(mainName, trivialService);
        for (int i= 1; i< runtimeCapabilities.length; i++) {
            serviceBuilder.addAliases(runtimeCapabilities[i].fromBaseCapability(address).getCapabilityServiceName());
        }

        trivialService.setValueSupplier(getValueSupplier(serviceBuilder, serviceTarget, mainName, address, context, resource.getModel()));

        installedForResource(commonDependencies(serviceBuilder)
                .setInitialMode(initialMode)
                .install(), resource);
    }

    protected void installedForResource(ServiceController<T> serviceController, Resource resource) {}

    protected abstract ValueSupplier<T> getValueSupplier(ServiceBuilder<T> serviceBuilder, ServiceTarget serviceTarget, ServiceName mainName, String address, OperationContext context, ModelNode model) throws OperationFailedException;

}
