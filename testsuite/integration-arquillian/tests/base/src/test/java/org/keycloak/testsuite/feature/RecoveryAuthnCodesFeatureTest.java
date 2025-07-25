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

package org.keycloak.testsuite.feature;

import org.junit.Test;
import org.keycloak.authentication.AuthenticatorSpi;
import org.keycloak.authentication.authenticators.browser.RecoveryAuthnCodesFormAuthenticatorFactory;
import org.keycloak.common.Profile;
import org.keycloak.testsuite.arquillian.annotation.DisableFeature;

public class RecoveryAuthnCodesFeatureTest extends AbstractFeatureStateTest {

    @Override
    public String getFeatureProviderId() {
        return RecoveryAuthnCodesFormAuthenticatorFactory.PROVIDER_ID;
    }

    @Override
    public String getFeatureSpiName() {
        return AuthenticatorSpi.SPI_NAME;
    }

    @Test
    public void featureEnabled() {
        testFeatureAvailability(true);
    }

    @Test
    @DisableFeature(value = Profile.Feature.RECOVERY_CODES, skipRestart = true)
    public void featureDisabled() {
        testFeatureAvailability(false);
    }
}
