/*
 * Copyright 2020 Scott Weeden and/or his affiliates
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

package org.keycloak.validation;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.oidc.OIDCClientRepresentation;

/**
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
public class ClientValidationContext extends DefaultValidationContext<ClientModel> {
    public ClientValidationContext(Event event, KeycloakSession session, ClientModel objectToValidate) {
        super(event, session, objectToValidate);
    }

    public static class OIDCContext extends ClientValidationContext {
        private final OIDCClientRepresentation oidcClient;

        public OIDCContext(Event event, KeycloakSession session, ClientModel objectToValidate, OIDCClientRepresentation oidcClient) {
            super(event, session, objectToValidate);
            this.oidcClient = oidcClient;
        }

        public OIDCClientRepresentation getOIDCClient() {
            return oidcClient;
        }
    }
}
