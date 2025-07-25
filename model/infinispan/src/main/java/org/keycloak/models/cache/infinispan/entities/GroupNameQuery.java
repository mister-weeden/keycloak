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

package org.keycloak.models.cache.infinispan.entities;

import org.keycloak.models.RealmModel;

public class GroupNameQuery extends AbstractRevisioned implements InRealm {
    private final String realm;
    private final String groupId;

    public GroupNameQuery(Long revisioned, String id, String groupId, RealmModel realm) {
        super(revisioned, id);
        this.realm = realm.getId();
        this.groupId = groupId;
    }

    public String getGroupId() {
        return groupId;
    }

    public String getRealm() {
        return realm;
    }

    @Override
    public String toString() {
        return "GroupNameQuery{" +
                "id='" + getId() + "'" +
                "realm='" + realm + '\'' +
                '}';
    }
}
