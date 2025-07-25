/*
 * Copyright 2016 Red Hat Inc and/or his affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.keycloak.testsuite.i18n;

import org.junit.After;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.UserBuilder;

/**
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public abstract class AbstractI18NTest extends AbstractTestRealmKeycloakTest {

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        UserBuilder user = UserBuilder.create()
                .username("login-test")
                .enabled(true)
                .email("login@test.com")
                .role("account", "manage-account")
                .password("password");
        RealmBuilder.edit(testRealm).user(user);
    }

    /**
     * Remove cookies at the end so that the next test will start out
     * using the default locale.
     */
    @After
    public void deleteCookies() {
        driver.manage().deleteAllCookies();
    }
}
