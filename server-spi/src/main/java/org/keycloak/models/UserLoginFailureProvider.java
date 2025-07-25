/*
 * Copyright 2021 Scott Weeden and/or his affiliates
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
package org.keycloak.models;

import org.keycloak.provider.Provider;

/**
 * @author <a href="mailto:mkanis@redhat.com">Martin Kanis</a>
 */
public interface UserLoginFailureProvider extends Provider {

    /**
     * Returns the {@link UserLoginFailureModel} for the given realm and user id.
     * @param realm {@link RealmModel}
     * @param userId {@link String} Id of the user.
     * @return Returns the {@link UserLoginFailureModel} for the given realm and user id.
     */
    UserLoginFailureModel getUserLoginFailure(RealmModel realm, String userId);

    /**
     * Adds a {@link UserLoginFailureModel} for the given realm and user id.
     * @param realm {@link RealmModel}
     * @param userId {@link String} Id of the user.
     * @return Returns newly created {@link UserLoginFailureModel}.
     */
    UserLoginFailureModel addUserLoginFailure(RealmModel realm, String userId);

    /**
     * Removes a {@link UserLoginFailureModel} for the given realm and user id.
     * @param realm {@link RealmModel}
     * @param userId {@link String} Id of the user.
     */
    void removeUserLoginFailure(RealmModel realm, String userId);

    /**
     * Removes all the {@link UserLoginFailureModel} for the given realm.
     * @param realm {@link RealmModel}
     */
    void removeAllUserLoginFailures(RealmModel realm);

}
