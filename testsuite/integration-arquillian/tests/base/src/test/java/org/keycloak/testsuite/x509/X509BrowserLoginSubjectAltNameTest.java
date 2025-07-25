/*
 * Copyright 2018 Scott Weeden and/or his affiliates
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

package org.keycloak.testsuite.x509;

import org.jboss.arquillian.drone.api.annotation.Drone;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.testsuite.util.HtmlUnitBrowser;
import org.openqa.selenium.WebDriver;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 8/12/2016
 */

public class X509BrowserLoginSubjectAltNameTest extends AbstractX509AuthenticationTest {

    @Drone
    @HtmlUnitBrowser
    private WebDriver htmlUnit;

    @Before
    public void replaceTheDefaultDriver() {
        replaceDefaultWebDriver(htmlUnit);
    }

    @BeforeClass
    public static void onBeforeTestClass() {
        configureHtmlUnit("/certs/clients/test-user-san-cert-test-user-key@localhost.p12");
    }

    @Test
    public void loginAsUserFromCertSANEmail() {
        x509BrowserLogin(createLoginSubjectAltNameEmail2UserAttributeConfig(), userId, "test-user@localhost", "test-user-altmail@localhost");
    }

    @Test
    public void loginAsUserFromCertSANUpn() {
        x509BrowserLogin(createLoginSubjectAltNameOtherName2UserAttributeConfig(), userId, "test-user@localhost", "test_upn_name@localhost");
    }
}
