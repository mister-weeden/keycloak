/*
 * Copyright 2017 Scott Weeden and/or his affiliates
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
package org.keycloak.models.cache.infinispan.authorization.entities;

import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionTicketScopeListQuery extends PermissionTicketListQuery implements InScope {

    private final String scopeId;

    public PermissionTicketScopeListQuery(Long revision, String id, String scopeId, Set<String> permissions, String serverId) {
        super(revision, id, permissions, serverId);
        this.scopeId = scopeId;
    }

    @Override
    public boolean isInvalid(Set<String> invalidations) {
        return super.isInvalid(invalidations) || invalidations.contains(getScopeId());
    }

    @Override
    public String getScopeId() {
        return scopeId;
    }
}