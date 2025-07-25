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

package org.keycloak.keys;

import org.keycloak.jose.jwk.JWK;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PublicKeyStorageUtils {

    static final JWK.Use DEFAULT_KEYUSE = JWK.Use.SIG;

    public static String getClientModelCacheKey(String realmId, String clientUuid) {
        return getClientModelCacheKey(realmId, clientUuid, DEFAULT_KEYUSE);
    }

    public static String getIdpModelCacheKey(String realmId, String idpInternalId) {
        return realmId + "::idp::" + idpInternalId;
    }

    public static String getClientModelCacheKey(String realmId, String clientUuid, JWK.Use keyUse) {
        return realmId + "::client::" + clientUuid + "::keyuse::" + keyUse;
    }

}
