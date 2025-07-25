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

package org.keycloak.testsuite.drone;

import java.util.concurrent.TimeUnit;

import org.jboss.arquillian.core.api.InstanceProducer;
import org.jboss.arquillian.core.api.annotation.Inject;
import org.jboss.arquillian.core.api.annotation.Observes;
import org.jboss.arquillian.drone.spi.DroneContext;
import org.jboss.arquillian.drone.spi.DronePoint;
import org.jboss.arquillian.drone.spi.event.AfterDroneEnhanced;
import org.jboss.arquillian.graphene.proxy.GrapheneProxyInstance;
import org.jboss.arquillian.graphene.proxy.Interceptor;
import org.jboss.arquillian.graphene.proxy.InvocationContext;
import org.jboss.arquillian.test.spi.annotation.ClassScoped;
import org.jboss.logging.Logger;
import org.keycloak.testsuite.util.WaitUtils;
import org.openqa.selenium.Capabilities;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.openqa.selenium.remote.RemoteWebDriver;

import java.io.File;
import java.net.MalformedURLException;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class KeycloakDronePostSetup {
    public static final String HTML_UNIT_SSL_KEYSTORE_PROP = "htmlunit-ssl-keystore";
    public static final String HTML_UNIT_SSL_KEYSTORE_PASSWORD_PROP = "htmlunit-ssl-keystore-password";
    public static final String HTML_UNIT_SSL_KEYSTORE_TYPE_PROP = "htmlunit-ssl-keystore-type";

    @Inject
    @ClassScoped // needed in BrowserDriverIgnoreDecider
    private InstanceProducer<WebDriver> webDriverProducer;

    protected static final Logger log = org.jboss.logging.Logger.getLogger(KeycloakDronePostSetup.class);

    public void configureWebDriver(@Observes AfterDroneEnhanced event, DroneContext droneContext) {
        DronePoint<?> dronePoint = event.getDronePoint();
        Object drone = droneContext.get(dronePoint).getInstance();

        if (drone instanceof RemoteWebDriver remoteWebDriver) {
            log.infof("Detected browser: %s %s", remoteWebDriver.getCapabilities().getBrowserName(), remoteWebDriver.getCapabilities().getBrowserVersion());
            webDriverProducer.set(remoteWebDriver);
        }

        if (drone instanceof WebDriver webDriver) {
            configureDriverSettings(webDriver);
            webDriverProducer.set(webDriver);
        } else {
            log.warn("Drone is not instanceof WebDriver for a desktop browser! Drone is " + drone);
        }

        if (drone instanceof GrapheneProxyInstance droneProxy) {
            if (drone instanceof HtmlUnitDriver) {
                droneProxy.registerInterceptor(new HtmlUnitInterceptor());
            }
        } else {
            log.warn("Drone is not instanceof GrapheneProxyInstance! Drone is " + drone);
        }
    }


    private void configureDriverSettings(WebDriver driver) {
        long implicitWaitMillis = WaitUtils.IMPLICIT_ELEMENT_WAIT_MILLIS;
        long pageLoadTimeoutMillis = WaitUtils.PAGELOAD_TIMEOUT_MILLIS;
        log.infof("Configuring driver settings. implicitWait=%d, pageLoadTimeout=%d", implicitWaitMillis, pageLoadTimeoutMillis);

        driver.manage().timeouts().implicitlyWait(implicitWaitMillis, TimeUnit.MILLISECONDS);
        driver.manage().timeouts().pageLoadTimeout(pageLoadTimeoutMillis, TimeUnit.MILLISECONDS);
        driver.manage().window().maximize();

        configureFirefoxDriver(driver);
        configureHtmlUnitDriver(driver);
    }

    private void configureFirefoxDriver(WebDriver driver) {
        if (driver instanceof FirefoxDriver firefoxDriver) {
            Capabilities capabilities = firefoxDriver.getCapabilities();
            FirefoxOptions options = new FirefoxOptions(capabilities);
            // disables extension automatic updates as we don't need it when running the test suite
            options.addPreference("extensions.update.enabled", "false");
            firefoxDriver.getCapabilities().merge(options);
        }
    }

    private void configureHtmlUnitDriver(WebDriver driver) {
        if (driver instanceof HtmlUnitDriver htmlUnitDriver) {
            final var keystore = System.getProperty(HTML_UNIT_SSL_KEYSTORE_PROP);
            final var keystorePassword = System.getProperty(HTML_UNIT_SSL_KEYSTORE_PASSWORD_PROP);
            final var keystoreType = System.getProperty(HTML_UNIT_SSL_KEYSTORE_TYPE_PROP);

            log.info("Check HtmlUnit driver TLS settings");

            if (keystore != null && keystorePassword != null && keystoreType != null) {
                log.infof("Keystore '%s', password '%s', type '%s'", keystore, keystorePassword, keystoreType);

                var options = htmlUnitDriver.getWebClient().getOptions();
                options.setUseInsecureSSL(true);
                try {
                    options.setSSLClientCertificateKeyStore(new File(keystore).toURI().toURL(), keystorePassword, keystoreType);
                } catch (MalformedURLException e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }

    public static class HtmlUnitInterceptor implements Interceptor {

        @Override
        public Object intercept(InvocationContext context) throws Throwable {
            if (context.getMethod().getName().equals("executeScript")) {

                String currentUrl = ((WebDriver) context.getTarget()).getCurrentUrl();
                int refreshCount = 0;

                while (true) {
                    try {
                        // htmlUnit is not able to run javascript on about:blank page
                        if ("about:blank".equals(currentUrl)) {
                            log.debug("Ignored JS as we are on about:blank page now");
                            return null;
                        }

                        return context.invoke();
                    } catch (UnsupportedOperationException e) {

                        // htmlUnit may require to refresh the page after the action
                        if ("Cannot execute JS against a plain text page".equals(e.getMessage())) {
                            refreshCount += 1;
                            if (refreshCount < 2) {
                                log.debugf("Will try to refresh current page: %s", currentUrl);
                                ((WebDriver) context.getProxy()).navigate().to(currentUrl);
                            } else {
                                log.debugf("Current page doesn't seem to support javascript. Current url: %s", currentUrl);
                                return null;
                            }
                        } else {
                            throw e;
                        }
                    }
                }


            } else {
                return context.invoke();
            }
        }

        @Override
        public int getPrecedence() {
            return -1;
        }

    }
}
