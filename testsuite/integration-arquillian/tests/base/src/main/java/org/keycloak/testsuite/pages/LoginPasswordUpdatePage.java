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

import org.keycloak.testsuite.util.UIUtils;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

import static org.keycloak.testsuite.util.UIUtils.isElementVisible;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class LoginPasswordUpdatePage extends LogoutSessionsPage {

    @FindBy(id = "password-new")
    private WebElement newPasswordInput;

    @FindBy(id = "password-confirm")
    private WebElement passwordConfirmInput;

    @FindBy(css = "[type=\"submit\"]")
    private WebElement submitButton;

    @FindBy(css = "div[class^='pf-v5-c-alert'], div[class^='alert-error']")
    private WebElement loginErrorMessage;

    @FindBy(className = "kc-feedback-text")
    private WebElement feedbackMessage;

    @FindBy(name = "cancel-aia")
    private WebElement cancelAIAButton;

    public void changePassword(String newPassword, String passwordConfirm) {
        newPasswordInput.sendKeys(newPassword);
        passwordConfirmInput.sendKeys(passwordConfirm);

        UIUtils.clickLink(submitButton);
    }

    public void cancel() {
        UIUtils.clickLink(cancelAIAButton);
    }

    public boolean isCurrent() {
        return PageUtils.getPageTitle(driver).equals("Update password");
    }

    public String getError() {
        return loginErrorMessage != null ? loginErrorMessage.getText() : null;
    }

    public String getFeedbackMessage() {
        return feedbackMessage.getText();
    }

    public boolean isCancelDisplayed() {
        return isElementVisible(cancelAIAButton);
    }

}
