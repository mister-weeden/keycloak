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
package org.keycloak.models.cache.infinispan;

import org.keycloak.models.RealmModel;
import org.keycloak.models.cache.infinispan.entities.AbstractRevisioned;
import org.keycloak.models.cache.infinispan.entities.InRealm;

public class CachedCount extends AbstractRevisioned implements InRealm {

    private final String realm;
    private final long count;

    public CachedCount(Long revision, RealmModel realm, String cacheKey, long count) {
        super(revision, cacheKey);
        this.realm = realm.getId();
        this.count = count;
    }

    @Override
    public String getRealm() {
        return realm;
    }

    public long getCount() {
        return count;
    }
}
