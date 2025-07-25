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

package org.keycloak.testsuite.oauth;

import org.junit.Test;
import org.keycloak.crypto.Algorithm;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class ClientAuthEdDSASignedJWTTest extends AbstractClientAuthSignedJWTTest {

    @Test
    public void testCodeToTokenRequestSuccessEd448usingJwksUri() throws Exception {
        testCodeToTokenRequestSuccess(Algorithm.EdDSA, Algorithm.Ed448, true);
    }

    @Test
    public void testCodeToTokenRequestSuccessEd25519usingJwks() throws Exception {
        testCodeToTokenRequestSuccess(Algorithm.EdDSA, Algorithm.Ed25519, false);
    }

    @Override
    protected String getKeyAlgorithmFromJwaAlgorithm(String jwaAlgorithm, String curve) {
        if (!Algorithm.EdDSA.equals(jwaAlgorithm)) {
            throw new RuntimeException("Unsupported signature algorithm: " + jwaAlgorithm);
        }
        switch (curve) {
            case Algorithm.Ed25519:
                return Algorithm.Ed25519;
            case Algorithm.Ed448:
                return Algorithm.Ed448;
            default :
                throw new RuntimeException("Unsupported signature curve " + curve);
        }
    }
}
