/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

/**
 * Constants used in the Elytron subsystem.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
interface ElytronDescriptionConstants {

    String ACTION = "action";
    String ACTIVE_SESSION_COUNT = "active-session-count";
    String ADD_ATTRIBUTE = "add-attribute";
    String ADD_PREFIX_ROLE_MAPPER = "add-prefix-role-mapper";
    String ADD_SUFFIX_ROLE_MAPPER = "add-suffix-role-mapper";
    String AGGREGATE_HTTP_SERVER_MECHANISM_FACTORY = "aggregate-http-server-mechanism-factory";
    String AGGREGATE_NAME_REWRITER = "aggregate-name-rewriter";
    String AGGREGATE_PRINCIPAL_DECODER = "aggregate-principal-decoder";
    String AGGREGATE_REALM = "aggregate-realm";
    String AGGREGATE_ROLE_MAPPER = "aggregate-role-mapper";
    String AGGREGATE_SASL_SERVER_FACTORY = "aggregate-sasl-server-factory";
    String ALIAS = "alias";
    String ALIAS_FILTER = "alias-filter";
    String ALGORITHM = "algorithm";
    String ALGORITHM_FROM = "algorithm-from";
    String AND = "and";
    String APPLICATION_BUFFER_SIZE = "application-buffer-size";
    String AS_RDN = "as-rdn";
    String ATTRIBUTE = "attribute";
    String ATTRIBUTE_MAPPING = "attribute-mapping";
    String ATTRIBUTES = "attributes";
    String AUTHENTICATION_LEVEL = "authentication-level";
    String AUTHENTICATION_OPTIONAL = "authentication-optional";
    String AUTHENTICATION_QUERY = "authentication-query";
    String AUTHENTICATION_REALM = "authentication-realm";
    String AUTHORIZATION_REALM = "authorization-realm";
    String AVAILABLE_MECHANISMS = "available-mechanisms";

    String BCRYPT = "bcrypt";
    String BCRYPT_MAPPER = "bcrypt-mapper";

    String CERTIFICATE = "certificate";
    String CERTIFICATE_CHAIN = "certificate-chain";
    String CERTIFICATES = "certificates";
    String CHAINED_NAME_REWRITER = "chained-name-rewriter";
    String CIPHER_SUITE = "cipher-suite";
    String CIPHER_SUITE_FILTER = "cipher-suite-filter";
    String CLASS_LOADING = "class-loading";
    String CLASS_NAME = "class-name";
    String CLASS_NAMES = "class-names";
    String CLEAR = "clear";
    String CLEAR_PASSWORD_MAPPER = "clear-password-mapper";
    String CONCATENATING_PRINCIPAL_DECODER = "concatenating-principal-decoder";
    String CONFIGURABLE_HTTP_SERVER_MECHANISM_FACTORY = "configurable-http-server-mechanism-factory";
    String CONFIGURABLE_SASL_SERVER_FACTORY = "configurable-sasl-server-factory";
    String CONFIGURATION = "configuration";
    String CONFIGURATION_FILE = "configuration-file";
    String CONFIGURATION_PROPERTIES = "configuration-properties";
    String CONSTANT = "constant";
    String CONSTANT_NAME_REWRITER = "constant-name-rewriter";
    String CONSTANT_PRINCIPAL_DECODER = "constant-principal-decoder";
    String CONSTANT_ROLE_MAPPER = "constant-role-mapper";
    String CORE_SERVICE = "core-service";
    String CREATION_DATE = "creation-date";
    String CREATION_TIME = "creation-time";
    String CREDENTIAL = "credential";
    String CREDENTIAL_MAPPING = "credential-mapping";
    String CREDENTIAL_NAME = "credential-name";
    String CREDENTIAL_SECURITY_FACTORIES = "credential-security-factories";
    String CREDENTIAL_SECURITY_FACTORY = "credential-security-factory";
    String CREDENTIALS = "credentials";
    String CUSTOM_CREDENTIAL_SECURITY_FACTORY = "custom-credential-security-factory";
    String CUSTOM_NAME_REWRITER = "custom-name-rewriter";
    String CUSTOM_PERMISSION_MAPPER = "custom-permission-mapper";
    String CUSTOM_PRINCIPAL_DECODER = "custom-principal-decoder";
    String CUSTOM_REALM = "custom-realm";
    String CUSTOM_MODIFIABLE_REALM = "custom-modifiable-realm";
    String CUSTOM_REALM_MAPPER = "custom-realm-mapper";
    String CUSTOM_ROLE_DECODER = "custom-role-decoder";
    String CUSTOM_ROLE_MAPPER = "custom-role-mapper";

    String DATA_SOURCE = "data-source";
    String DEBUG = "debug";
    String DEFAULT_REALM = "default-realm";
    String DELEGATE_REALM_MAPPER = "delegate-realm-mapper";
    String DIGEST = "digest";
    String DIR_CONTEXT = "dir-context";
    String DIRECT_VERIFICATION = "direct-verification";

    String EMPTY = "empty";
    String EMPTY_ROLE_DECODER = "empty-role-decoder";
    String ENABLE_CONNECTION_POOLING = "enable-connection-pooling";
    String ENABLING = "enabling";
    String ENCODED = "encoded";
    String ENTRY_TYPE = "entry-type";

    String FILE = "file";
    String FILESYSTEM_REALM = "filesystem-realm";
    String FILTER = "filter";
    String FILTER_BASE_DN = "filter-base-dn";
    String FILTERS = "filters";
    String FINAL_NAME_REWRITER = "final-name-rewriter";
    String FINGER_PRINT = "finger-print";
    String FINGER_PRINTS = "finger-prints";
    String FIRST = "first";
    String FORMAT = "format";
    String FROM = "from";

    String GREATER_THAN = "greater-than";
    String GROUPS = "groups";
    String GROUPS_ATTRIBUTE = "groups-attribute";
    String GROUPS_PROPERTIES = "groups-properties";

    String HOST_NAME = "host-name";
    String HASH_FROM = "hash-from";
    String HTTP = "http";
    String HTTP_AUTHENTICATION_FACTORY = "http-authentication-factory";
    String HTTP_SERVER_MECHANISM_FACTORY = "http-server-mechanism-factory";
    String HTTP_SERVER_FACTORIES = "http-server-factories";

    String IDENTITY = "identity";
    String IDENTITY_MAPPING = "identity-mapping";
    String IMPLEMENTATION = "implementation";
    String INDEX = "index";
    String INFO = "info";
    String INVALIDATE = "invalidate";
    String ISSUER = "issuer";
    String ITERATION_COUNT = "iteration-count";
    String ITERATION_COUNT_INDEX = "iteration-count-index";
    String ITERATOR_FILTER = "iterator-filter";
    String ITERATOR_FILTER_ARGS = "iterator-filter-args";

    String JDBC_REALM = "jdbc-realm";
    String JOINER = "joiner";

    String KERBEROS_SECURITY_FACTORY = "kerberos-security-factory";
    String KEY = "key";
    String KEY_MANAGER = "key-manager";
    String KEY_MANAGERS = "key-managers";
    String KEY_STORE = "key-store";
    String KEY_STORE_REALM = "key-store-realm";
    String KEY_STORES = "key-stores";

    String LAST_ACCESSED_TIME = "last-accessed-time";
    String LDAP_REALM = "ldap-realm";
    String LEFT = "left";
    String LESS_THAN = "less-than";
    String LEVELS = "levels";
    String LOAD = "load";
    String LOAD_SERVICES = "load-services";
    String LOADED_PROVIDER = "loaded-provider";
    String LOADED_PROVIDERS = "loaded-providers";
    String LOCAL_CERTIFICATES = "local-certificates";
    String LOCAL_PRINCIPAL = "local-principal";
    String LOGICAL_OPERATION = "logical-operation";
    String LOGICAL_PERMISSION_MAPPER = "logical-permission-mapper";
    String LOGICAL_ROLE_MAPPER = "logical-role-mapper";

    String MAPPED_REGEX_REALM_MAPPER = "mapped-regex-realm-mapper";
    String MAPPERS = "mappers";
    String MAPPING_MODE = "mapping-mode";
    String MATCH = "match";
    String MAXIMUM_SEGMENTS = "maximum-segments";
    String MAXIMUM_SESSION_CACHE_SIZE = "maximum-session-cache-size";
    String MECHANISM = "mechanism";
    String MECHANISM_CONFIGURATION = "mechanism-configuration";
    String MECHANISM_CONFIGURATIONS = "mechanism-configurations";
    String MECHANISM_NAME = "mechanism-name";
    String MECHANISM_OIDS = "mechanism-oids";
    String MECHANISM_PROVIDER_FILTERING_SASL_SERVER_FACTORY = "mechanism-provider-filtering-sasl-server-factory";
    String MECHANISM_REALM = "mechanism-realm";
    String MECHANISM_REALM_CONFIGURATION = "mechanism-realm-configuration";
    String MECHANISM_REALM_CONFIGURATIONS = "mechanism-realm-configurations";
    String MINIMUM_REMAINING_LIFETIME = "minimum-remaining-lifetime";
    String MINUS = "minus";
    String MODIFIABLE_SECURITY_REALM = "modifiable-security-realm";
    String MODIFIED = "modified";
    String MODULE = "module";
    String MODULE_REFERENCE = "module-reference";

    String NAME = "name";
    String NAME_REWRITER = "name-rewriter";
    String NAME_REWRITERS = "name-rewriters";
    String NEED_CLIENT_AUTH = "need-client-auth";
    String NEW_IDENTITY_ATTRIBUTES = "new-identity-attributes";
    String NEW_IDENTITY_PARENT_DN = "new-identity-parent-dn";
    String NOT_AFTER = "not-after";
    String NOT_BEFORE = "not-before";

    String OID = "oid";
    String OTP_CREDENTIAL_MAPPER = "otp-credential-mapper";
    String OR = "or";

    String PACKET_BUFFER_SIZE = "packet-buffer-size";
    String PATH = "path";
    String PASSWORD = "password";
    String PASSWORD_INDEX = "password-index";
    String PATTERN = "pattern";
    String PATTERN_FILTER = "pattern-filter";
    String PEER_CERTIFICATES = "peer-certificates";
    String PEER_HOST = "peer-host";
    String PEER_PORT = "peer-port";
    String PEER_PRINCIPAL = "peer-principal";
    String PERMISSION = "permission";
    String PERMISSIONS = "permissions";
    String PERMISSION_MAPPER = "permission-mapper";
    String PERMISSION_MAPPING = "permission-mapping";
    String PERMISSION_MAPPINGS = "permission-mappings";
    String PLAIN_TEXT = "plain-text";
    String POST_REALM_NAME_REWRITER = "post-realm-name-rewriter";
    String PRE_REALM_NAME_REWRITER = "pre-realm-name-rewriter";
    String PREDEFINED_FILTER = "predefined-filter";
    String PREFIX = "prefix";
    String PRINCIPAL = "principal";
    String PRINCIPALS = "principals";
    String PRINCIPAL_DECODER = "principal-decoder";
    String PRINCIPAL_DECODERS = "principal-decoders";
    String PRINCIPAL_QUERY = "principal-query";
    String PROPERTIES = "properties";
    String PROPERTIES_REALM = "properties-realm";
    String PROPERTY = "property";
    String PROPERTY_LIST = "property-list";
    String PROTOCOL = "protocol";
    String PROTOCOLS = "protocols";
    String PROVIDER = "provider";
    String PROVIDER_HTTP_SERVER_MECHANISM_FACTORY = "provider-http-server-mechanism-factory";
    String PROVIDER_LOADER = "provider-loader";
    String PROVIDER_LOADERS = "provider-loaders";
    String PROVIDER_NAME = "provider-name";
    String PROVIDER_SASL_SERVER_FACTORY = "provider-sasl-server-factory";
    String PROVIDER_VERSION = "provider-version";
    String PROVIDERS = "providers";
    String PUBLIC_KEY = "public-key";

    String RDN_IDENTIFIER = "rdn-identifier";
    String READ_IDENTITY = "read-identity";
    String REALM = "realm";
    String REALM_MAP = "realm-map";
    String REALM_MAPPER = "realm-mapper";
    String REALM_MAPPING = "realm-mapping";
    String REALM_NAME = "realm-name";
    String REALMS = "realms";
    String REGEX_NAME_REWRITER = "regex-name-rewriter";
    String REGEX_NAME_VALIDATING_REWRITER = "regex-name-validating-rewriter";
    String REGISTER = "register";
    String RELATIVE_TO = "relative-to";
    String REMOVE_ATTRIBUTE = "remove-attribute";
    String REPLACE_ALL = "replace-all";
    String REPLACEMENT = "replacement";
    String REQUEST_LIFETIME = "request-lifetime";
    String REQUIRED = "required";
    String REQUIRED_OIDS = "required-oids";
    String REVERSE = "reverse";
    String RIGHT = "right";
    String ROLE_DECODER = "role-decoder";
    String ROLE_MAPPER = "role-mapper";
    String ROLE_MAPPERS = "role-mappers";
    String ROLES = "roles";

    String SALT = "salt";
    String SALT_INDEX = "salt-index";
    String SALTED_SIMPLE_DIGEST = "salted-simple-digest";
    String SALTED_SIMPLE_DIGEST_MAPPER = "salted-simple-digest-mapper";
    String SASL = "sasl";
    String SASL_AUTHENTICATION_FACTORY = "sasl-authentication-factory";
    String SASL_SERVER_FACTORIES = "sasl-server-factories";
    String SASL_SERVER_FACTORY = "sasl-server-factory";
    String SCRAM_MAPPER = "scram-mapper";
    String SEARCH_BASE_DN = "search-base-dn";
    String SECURITY_DOMAIN = "security-domain";
    String SECURITY_DOMAINS = "security-domains";
    String SECURITY_PROPERTIES = "security-properties";
    String SECURITY_PROPERTY = "security-property";
    String SECURITY_REALMS = "security-realms";
    String SELECTION_CRITERIA = "selection-criteria";
    String SEED_FROM = "seed-from";
    String SERVER_NAME = "server-name";
    String SERIAL_NUMBER = "serial-number";
    String SERVER = "server";
    String SERVER_SSL_CONTEXT = "server-ssl-context";
    String SERVER_SSL_CONTEXTS = "server-ssl-contexts";
    String SESSION_TIMEOUT = "session-timeout";
    String SET_PASSWORD = "set-password";
    String SERVICE = "service";
    String SERVICE_LOADER_HTTP_SERVER_MECHANISM_FACTORY = "service-loader-http-server-mechanism-factory";
    String SERVICE_LOADER_SASL_SERVER_FACTORY = "service-loader-sasl-server-factory";
    String SERVICES = "services";
    String SEQUENCE_FROM = "sequence-from";
    String SIGNATURE = "signature";
    String SIGNATURE_ALGORITHM = "signature-algorithm";
    String SIMPLE_DIGEST = "simple-digest";
    String SIMPLE_DIGEST_MAPPER = "simple-digest-mapper";
    String SIMPLE_PERMISSION_MAPPER = "simple-permission-mapper";
    String SIMPLE_REGEX_REALM_MAPPER = "simple-regex-realm-mapper";
    String SIMPLE_ROLE_DECODER = "simple-role-decoder";
    String SINGLE_SIGN_ON = "single-sign-on";
    String SIZE = "size";
    String SQL = "sql";
    String SSL_SESSION = "ssl-session";
    String START_SEGMENT = "start-segment";
    String STATE = "state";
    String STORE = "store";
    String SUBJECT = "subject";
    String SUFFIX = "suffix";
    String SUPPORTED_CREDENTIAL = "supported-credential";
    String SUPPORTED_CREDENTIALS = "supported-credentials";
    String SYNCHRONIZED = "synchronized";

    String TARGET_NAME = "target-name";
    String TLS = "tls";
    String TO = "to";
    String TRUST_MANAGER = "trust-manager";
    String TRUST_MANAGERS = "trust-managers";
    String TRUSTED_SECURITY_DOMAINS = "trusted-security-domains";
    String TYPE = "type";

    String UNLESS = "unless";
    String URL = "url";
    String USE_RECURSIVE_SEARCH = "use-recursive-search";
    String USERS_PROPERTIES = "users-properties";
    String USER_PASSWORD_MAPPER = "user-password-mapper";

    String VALID = "valid";
    String VALUE = "value";
    String VERIFIABLE = "verifiable";
    String VERSION = "version";
    String VERSION_COMPARISON = "version-comparison";

    String WANT_CLIENT_AUTH = "want-client-auth";
    String WATCH = "watch";
    String WRITABLE = "writable";

    String X500_ATTRIBUTE_PRINCIPAL_DECODER = "x500-attribute-principal-decoder";
    String XOR = "xor";

}

