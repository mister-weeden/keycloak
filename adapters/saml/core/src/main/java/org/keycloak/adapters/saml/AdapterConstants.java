/*
 * Copyright 2016 Scott Weeden and/or his affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.adapters.saml;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class AdapterConstants {
    public static final String AUTH_DATA_PARAM_NAME="org.keycloak.saml.xml.adapterConfig";
    public static final String REPLICATION_CONFIG_CONTAINER_PARAM_NAME = "org.keycloak.saml.replication.container";
    public static final String REPLICATION_CONFIG_SSO_CACHE_PARAM_NAME = "org.keycloak.saml.replication.cache.sso";
    public static final String AUTHENTICATION_EXPIRED_MESSAGE = "authentication_expired";
}
