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

package org.keycloak.testsuite.pages;

import org.keycloak.testsuite.util.DroneUtils;
import org.keycloak.testsuite.util.oauth.OAuthClient;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

import static org.keycloak.testsuite.util.UIUtils.clickLink;
import static org.keycloak.testsuite.util.ServerURLs.removeDefaultPorts;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class AppPage extends AbstractPage {

    @FindBy(id = "account")
    private WebElement accountLink;

    public void open() {
        DroneUtils.getCurrentDriver().navigate().to(OAuthClient.APP_AUTH_ROOT);
    }

    @Override
    public boolean isCurrent() {
        return removeDefaultPorts(DroneUtils.getCurrentDriver().getCurrentUrl()).startsWith(OAuthClient.APP_AUTH_ROOT);
    }

    public RequestType getRequestType() {
        return RequestType.valueOf(DroneUtils.getCurrentDriver().getTitle());
    }

    public void openAccount() {
        clickLink(accountLink);
    }

    public WebElement getAccountLink() {
        return accountLink;
    }

    public enum RequestType {
        AUTH_RESPONSE, LOGOUT_REQUEST, APP_REQUEST
    }

    public void logout(String idTokenHint) {
        oauth.logoutForm().idTokenHint(idTokenHint).withRedirect().open();
    }



}
