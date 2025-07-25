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

package org.keycloak.testsuite.forms;

import org.keycloak.testsuite.AbstractChangeImportedUserPasswordsTest;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

/**
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public abstract class AbstractFlowTest extends AbstractChangeImportedUserPasswordsTest {

    protected AuthenticationFlowRepresentation findFlowByAlias(String alias) {
        for (AuthenticationFlowRepresentation rep : testRealm().flows().getFlows()) {
            if (rep.getAlias().equals(alias)) return rep;
        }

        return null;
    }

    protected void setRegistrationFlow(AuthenticationFlowRepresentation flow) {
        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setRegistrationFlow(flow.getAlias());
        testRealm().update(realm);
    }
}
