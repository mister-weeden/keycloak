/*
 * Copyright 2024 Scott Weeden and/or his affiliates
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

package org.keycloak.protocol.oid4vc.issuance.signing;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.Format;

public class JwtCredentialSignerFactory implements CredentialSignerFactory {

    @Override
    public String getSupportedFormat() {
        return Format.JWT_VC;
    }

    @Override
    public CredentialSigner<String> create(KeycloakSession session) {
        return new JwtCredentialSigner(session);
    }
}
