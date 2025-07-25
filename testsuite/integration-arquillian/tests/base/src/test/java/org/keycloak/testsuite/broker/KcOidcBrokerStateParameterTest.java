/*
 * Copyright 2020 Scott Weeden and/or his affiliates
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
 *
 */

package org.keycloak.testsuite.broker;

import org.hamcrest.Matchers;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.common.util.UriUtils;
import org.keycloak.events.EventType;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.pages.LoginExpiredPage;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.keycloak.testsuite.broker.BrokerTestTools.waitForPage;

/**
 * Tests related to OIDC "state" parameter used in the OIDC AuthenticationResponse sent by the IDP to the SP endpoint
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class KcOidcBrokerStateParameterTest extends AbstractInitializedBaseBrokerTest {

    @Page
    protected AppPage appPage;

    @Page
    protected LoginExpiredPage loginExpiredPage;

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return KcOidcBrokerConfiguration.INSTANCE;
    }

    @Test
    public void testMissingStateParameter() {
        final String consumerEndpointUrl = getURLOfOIDCIdpEndpointOnConsumerSide() + "?code=foo123";

        events.clear();

        // Manually open the consumer endpoint URL
        driver.navigate().to(consumerEndpointUrl);
        waitForPage(driver, "sign in to consumer", true);

        errorPage.assertCurrent();
        assertThat(errorPage.getError(), Matchers.is("Missing state parameter in response from identity provider."));

        // Test that only loginEvent happened on consumer side. There should *not* be request sent to provider realm codeToToken endpoint (Assert that event is not there)
        String consumerRealmId = realmsResouce().realm(bc.consumerRealmName()).toRepresentation().getId();
        events.expect(EventType.IDENTITY_PROVIDER_LOGIN_ERROR)
                .clearDetails()
                .session((String) null)
                .realm(consumerRealmId)
                .user((String) null)
                .client((String) null)
                .error("identity_provider_login_failure")
                .assertEvent();

        events.assertEmpty();
    }


    @Test
    public void testIncorrectStateParameter() throws Exception {
        final String consumerEndpointUrl = KeycloakUriBuilder.fromUri(getURLOfOIDCIdpEndpointOnConsumerSide())
                .queryParam(OAuth2Constants.CODE, "foo456")
                .queryParam(OAuth2Constants.STATE, "someIncorrectState")
                .build().toString();

        events.clear();

        // Manually open the consumer endpoint URL
        String consumerRealmId = realmsResouce().realm(bc.consumerRealmName()).toRepresentation().getId();
        driver.navigate().to(consumerEndpointUrl);

        // Test that only loginEvent happened on consumer side. There should *not* be request sent to provider realm codeToToken endpoint (Assert that event is not there)
        events.expect(EventType.IDENTITY_PROVIDER_LOGIN_ERROR)
                .clearDetails()
                .session((String) null)
                .realm(consumerRealmId)
                .user((String) null)
                .client((String) null)
                .error("invalidRequestMessage")
                .assertEvent();

        events.assertEmpty();
    }


    @Test
    public void testCorrectStateParameterButIncorrectCode() {
        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());

        waitForPage(driver, "sign in to", true);
        loginPage.clickSocial(bc.getIDPAlias());
        waitForPage(driver, "sign in to", true);

        // Get the "state", which was generated by "consumer" before sending OIDC AuthenticationRequest to "provider"
        String url = driver.getCurrentUrl();
        String stateParamValue = UriUtils.decodeQueryString(url).getFirst(OAuth2Constants.STATE);

        final String consumerEndpointUrl = KeycloakUriBuilder.fromUri(getURLOfOIDCIdpEndpointOnConsumerSide())
                .queryParam(OAuth2Constants.CODE, "foo123")
                .queryParam(OAuth2Constants.STATE, stateParamValue)
                .build().toString();

        events.clear();

        // Manually open the consumer endpoint URL
        String providerRealmId = realmsResouce().realm(bc.providerRealmName()).toRepresentation().getId();
        String consumerRealmId = realmsResouce().realm(bc.consumerRealmName()).toRepresentation().getId();
        driver.navigate().to(consumerEndpointUrl);

        // Check that loginError on consumer side was triggered. Also CodeToToken request was sent to the "provider", but failed due the incorrect code
        events.expect(EventType.CODE_TO_TOKEN_ERROR)
                .clearDetails()
                .session((String) null)
                .realm(providerRealmId)
                .user((String) null)
                .client("brokerapp")
                .error("invalid_code")
                .assertEvent();

        events.expect(EventType.IDENTITY_PROVIDER_LOGIN_ERROR)
                .clearDetails()
                .session((String) null)
                .realm(consumerRealmId)
                .user((String) null)
                .client("broker-app")
                .error("identity_provider_login_failure")
                .assertEvent();

        // Re-send the request to same URL. There should *not* be additional
        // request sent to provider realm codeToToken endpoint due the "state" already used on consumer side (Assert that CodeToToken event is not there)
        // The consumer should display "Page has expired" error
        driver.navigate().to(consumerEndpointUrl);
        loginExpiredPage.assertCurrent();

        events.assertEmpty();

    }

    // Return the endpoint on consumer side where the IDentity Provider redirects the browser after successful authentication on IDP side.
    private String getURLOfOIDCIdpEndpointOnConsumerSide() {
        BrokerConfiguration brokerConfig = getBrokerConfiguration();
        return oauth.AUTH_SERVER_ROOT + "/realms/" + brokerConfig.consumerRealmName() + "/broker/" + brokerConfig.getIDPAlias() + "/endpoint";
    }


}
