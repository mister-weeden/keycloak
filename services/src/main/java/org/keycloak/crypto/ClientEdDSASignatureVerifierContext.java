/*
 * Copyright 2023 Scott Weeden and/or his affiliates
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

package org.keycloak.crypto;

import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.keys.loader.PublicKeyStorageManager;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class ClientEdDSASignatureVerifierContext extends AsymmetricSignatureVerifierContext {
    public ClientEdDSASignatureVerifierContext(KeycloakSession session, ClientModel client, JWSInput input) throws VerificationException {
        super(getKey(session, client, input));
    }

    private static KeyWrapper getKey(KeycloakSession session, ClientModel client, JWSInput input) throws VerificationException {
        KeyWrapper key = PublicKeyStorageManager.getClientPublicKeyWrapper(session, client, input);
        if (key == null) {
            throw new VerificationException("Key not found");
        }
        if (!KeyType.OKP.equals(key.getType())) {
            throw new VerificationException("Key Type is not OKP: " + key.getType());
        }
        if (key.getCurve() == null) {
            throw new VerificationException("EdDSA key should have curve defined");
        }
        if (key.getAlgorithm() == null) {
            // defaults to the algorithm set to the JWS
            // validations should be performed prior to verifying signature in case there are restrictions on the algorithms
            // that can used for signing
            key.setAlgorithm(input.getHeader().getRawAlgorithm());
        }
        return key;
    }

}
