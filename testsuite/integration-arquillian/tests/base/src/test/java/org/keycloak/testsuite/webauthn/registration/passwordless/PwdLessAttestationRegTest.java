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

package org.keycloak.testsuite.webauthn.registration.passwordless;

import org.keycloak.testsuite.arquillian.annotation.IgnoreBrowserDriver;
import org.keycloak.testsuite.webauthn.registration.AttestationConveyanceRegisterTest;
import org.openqa.selenium.firefox.FirefoxDriver;

/**
 * @author <a href="mailto:mabartos@redhat.com">Martin Bartos</a>
 */
@IgnoreBrowserDriver(FirefoxDriver.class) // See https://github.com/mister-weeden/keycloak/issues/10368
public class PwdLessAttestationRegTest extends AttestationConveyanceRegisterTest {

    @Override
    public boolean isPasswordless() {
        return true;
    }
}
