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

package org.keycloak.models.cache.infinispan.events;

import java.util.Set;

import org.infinispan.protostream.annotations.ProtoFactory;
import org.infinispan.protostream.annotations.ProtoTypeId;
import org.keycloak.marshalling.Marshalling;
import org.keycloak.models.cache.infinispan.UserCacheManager;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@ProtoTypeId(Marshalling.USER_CONSENTS_UPDATED_EVENT)
public class UserConsentsUpdatedEvent extends InvalidationEvent implements UserCacheInvalidationEvent {

    private UserConsentsUpdatedEvent(String id) {
        super(id);
    }

    @ProtoFactory
    public static UserConsentsUpdatedEvent create(String id) {
        return new UserConsentsUpdatedEvent(id);
    }

    @Override
    public String toString() {
        return String.format("UserConsentsUpdatedEvent [ userId=%s ]", getId());
    }

    @Override
    public void addInvalidations(UserCacheManager userCache, Set<String> invalidations) {
        userCache.consentInvalidation(getId(), invalidations);
    }

}
