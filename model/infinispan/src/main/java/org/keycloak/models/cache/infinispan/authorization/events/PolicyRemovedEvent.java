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

package org.keycloak.models.cache.infinispan.authorization.events;

import java.util.Set;

import org.infinispan.protostream.annotations.ProtoFactory;
import org.infinispan.protostream.annotations.ProtoTypeId;
import org.keycloak.marshalling.Marshalling;
import org.keycloak.models.cache.infinispan.authorization.StoreFactoryCacheManager;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@ProtoTypeId(Marshalling.POLICY_REMOVED_EVENT)
public class PolicyRemovedEvent extends BasePolicyEvent {

    @ProtoFactory
    PolicyRemovedEvent(String id, String name, Set<String> resources, Set<String> resourceTypes, Set<String> scopes, String serverId) {
        super(id, name, resources, resourceTypes, scopes, serverId);
    }

    public static PolicyRemovedEvent create(String id, String name, Set<String> resources, Set<String> resourceTypes, Set<String> scopes, String serverId) {
        return new PolicyRemovedEvent(id, name, resources, resourceTypes, scopes, serverId);
    }

    @Override
    public void addInvalidations(StoreFactoryCacheManager cache, Set<String> invalidations) {
        cache.policyRemoval(getId(), name, resources, resourceTypes, scopes, serverId, invalidations);
    }
}
