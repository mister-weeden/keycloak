/*
 * Copyright 2023 Scott Weeden and/or his affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.keycloak.testsuite.user.profile;

import org.keycloak.models.KeycloakSession;
import org.keycloak.userprofile.DeclarativeUserProfileProviderFactory;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CustomUserProfileProviderFactory extends DeclarativeUserProfileProviderFactory {

    public static final String ID = "custom-user-profile";

    @Override
    public CustomUserProfileProvider create(KeycloakSession session) {
        return new CustomUserProfileProvider(session, this);
    }

    @Override
    public int order() {
        return super.order() - 1;
    }

    @Override
    public String getId() {
        return ID;
    }
}
