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
package org.keycloak.sdjwt;

import java.util.Objects;

import org.keycloak.jose.jws.crypto.HashUtils;

/**
 * Handles hash production for a decoy entry from the given salt.
 * 
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 * 
 */
public abstract class DecoyEntry {
    private final SdJwtSalt salt;

    protected DecoyEntry(SdJwtSalt salt) {
        this.salt = Objects.requireNonNull(salt, "DecoyEntry always requires a non null salt");
    }

    public SdJwtSalt getSalt() {
        return salt;
    }

    public String getDisclosureDigest(String hashAlg) {
        return SdJwtUtils.encodeNoPad(HashUtils.hash(hashAlg, salt.toString().getBytes()));
    }
}
