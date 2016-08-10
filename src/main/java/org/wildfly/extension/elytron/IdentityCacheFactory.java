package org.wildfly.extension.elytron;

import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.http.HttpServerRequest;

import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface IdentityCacheFactory {
    IdentityCache create(Supplier<HttpServerRequest> request);
}
