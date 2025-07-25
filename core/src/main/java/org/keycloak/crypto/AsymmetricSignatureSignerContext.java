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
package org.keycloak.crypto;

import java.security.PrivateKey;
import java.security.Signature;

public class AsymmetricSignatureSignerContext implements SignatureSignerContext {

    private final KeyWrapper key;

    public AsymmetricSignatureSignerContext(KeyWrapper key) throws SignatureException {
        this.key = key;
    }

    @Override
    public String getKid() {
        return key.getKid();
    }

    @Override
    public String getAlgorithm() {
        return key.getAlgorithmOrDefault();
    }

    @Override
    public String getHashAlgorithm() {
        return JavaAlgorithm.getJavaAlgorithmForHash(key.getAlgorithmOrDefault(), key.getCurve());
    }

    @Override
    public byte[] sign(byte[] data) throws SignatureException {
        try {
            Signature signature = Signature.getInstance(JavaAlgorithm.getJavaAlgorithm(key.getAlgorithmOrDefault(), key.getCurve()));
            signature.initSign((PrivateKey) key.getPrivateKey());
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new SignatureException("Signing failed", e);
        }
    }

}
