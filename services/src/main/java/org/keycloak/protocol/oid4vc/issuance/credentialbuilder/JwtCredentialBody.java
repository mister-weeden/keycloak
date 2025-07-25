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

package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.jboss.logging.Logger;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSBuilder;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class JwtCredentialBody implements CredentialBody {

    private static final Logger LOGGER = Logger.getLogger(JwtCredentialBody.class);

    private final JWSBuilder.EncodingBuilder jwsEncodingBuilder;

    public JwtCredentialBody(JWSBuilder.EncodingBuilder jwsEncodingBuilder) {
        this.jwsEncodingBuilder = jwsEncodingBuilder;
    }

    public void addKeyBinding(JWK jwk) throws CredentialBuilderException {
        LOGGER.warnf("Key binding is not yet implemented for JWT credentials");
    }

    public String sign(SignatureSignerContext signatureSignerContext) {
        return jwsEncodingBuilder.sign(signatureSignerContext);
    }
}
