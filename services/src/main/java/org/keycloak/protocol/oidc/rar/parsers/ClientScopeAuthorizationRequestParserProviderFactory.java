/*
 * Copyright 2022 Scott Weeden and/or his affiliates
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
package org.keycloak.protocol.oidc.rar.parsers;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.rar.AuthorizationRequestParserProvider;
import org.keycloak.protocol.oidc.rar.AuthorizationRequestParserProviderFactory;
import org.keycloak.protocol.oidc.rar.parsers.ClientScopeAuthorizationRequestParser;

/**
 * @author <a href="mailto:dgozalob@redhat.com">Daniel Gozalo</a>
 */
public class ClientScopeAuthorizationRequestParserProviderFactory implements AuthorizationRequestParserProviderFactory {

    public static final String CLIENT_SCOPE_PARSER_ID = "client-scope";

    @Override
    public AuthorizationRequestParserProvider create(KeycloakSession session) {
        return new ClientScopeAuthorizationRequestParser(session.getContext().getClient());
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return CLIENT_SCOPE_PARSER_ID;
    }
}
