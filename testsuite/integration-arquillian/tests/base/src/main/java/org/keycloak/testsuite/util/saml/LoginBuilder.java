/*
 * Copyright 2017 Scott Weeden and/or his affiliates
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
package org.keycloak.testsuite.util.saml;

import org.keycloak.testsuite.util.SamlClientBuilder;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.admin.Users;
import org.keycloak.testsuite.util.SamlClient.Step;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.hamcrest.Matchers;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.keycloak.testsuite.admin.Users.getPasswordOf;
import static org.keycloak.testsuite.util.Matchers.statusCodeIsHC;

/**
 *
 * @author hmlnarik
 */
public class LoginBuilder implements Step {

    private final SamlClientBuilder clientBuilder;
    private UserRepresentation user;
    private boolean sso = false;
    private String idpAlias;

    public LoginBuilder(SamlClientBuilder clientBuilder) {
        this.clientBuilder = clientBuilder;
    }

    @Override
    public HttpUriRequest perform(CloseableHttpClient client, URI currentURI, CloseableHttpResponse currentResponse, HttpClientContext context) throws Exception {
        if (sso) {
            return null;    // skip this step
        } else {
            assertThat(currentResponse, statusCodeIsHC(Response.Status.OK));
            String loginPageText = EntityUtils.toString(currentResponse.getEntity(), StandardCharsets.UTF_8);
            assertThat(loginPageText, containsString("login"));

            return handleLoginPage(loginPageText, currentURI);
        }
    }

    public SamlClientBuilder build() {
        return this.clientBuilder;
    }

    public LoginBuilder user(UserRepresentation user) {
        this.user = user;
        return this;
    }

    public LoginBuilder user(String userName, String password) {
        this.user = new UserRepresentation();
        this.user.setUsername(userName);
        Users.setPasswordFor(user, password);
        return this;
    }

    public LoginBuilder sso(boolean sso) {
        this.sso = sso;
        return this;
    }

    /**
     * When the step is executed and {@code idpAlias} is not {@code null}, it attempts to find and follow the link to
     * identity provider with the given alias.
     * @param idpAlias
     * @return
     */
    public LoginBuilder idp(String idpAlias) {
        this.idpAlias = idpAlias;
        return this;
    }

    /**
     * Prepares a GET/POST request for logging the given user into the given login page. The login page is expected
     * to have at least input fields with id "username" and "password".
     *
     * @param user
     * @param loginPage
     * @return
     */
    private HttpUriRequest handleLoginPage(String loginPage, URI currentURI) {
        if (idpAlias != null) {
            org.jsoup.nodes.Document theLoginPage = Jsoup.parse(loginPage);
            Element socialLink = theLoginPage.getElementById("social-" + this.idpAlias);
            assertThat("Unknown idp: " + this.idpAlias, socialLink, Matchers.notNullValue());
            final String link = socialLink.attr("href");
            assertThat("Invalid idp link: " + this.idpAlias, link, Matchers.notNullValue());
            return new HttpGet(currentURI.resolve(link));
        }

        return handleLoginPage(user, loginPage);
    }

    public static HttpUriRequest handleLoginPage(UserRepresentation user, String loginPage) {
        String username = user.getUsername();
        String password = getPasswordOf(user);
        org.jsoup.nodes.Document theLoginPage = Jsoup.parse(loginPage);

        List<NameValuePair> parameters = new LinkedList<>();
        for (Element form : theLoginPage.getElementsByTag("form")) {
            String method = form.attr("method");
            String action = form.attr("action");
            boolean isPost = method != null && "post".equalsIgnoreCase(method);

            for (Element input : form.getElementsByTag("input")) {
                if (Objects.equals(input.id(), "username")) {
                    parameters.add(new BasicNameValuePair(input.attr("name"), username));
                } else if (Objects.equals(input.id(), "password")) {
                    parameters.add(new BasicNameValuePair(input.attr("name"), password));
                } else {
                    parameters.add(new BasicNameValuePair(input.attr("name"), input.val()));
                }
            }

            if (isPost) {
                HttpPost res = new HttpPost(action);

                UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
                res.setEntity(formEntity);

                return res;
            } else {
                UriBuilder b = UriBuilder.fromPath(action);
                for (NameValuePair parameter : parameters) {
                    b.queryParam(parameter.getName(), parameter.getValue());
                }
                return new HttpGet(b.build());
            }
        }

        throw new IllegalArgumentException("Invalid login form: " + loginPage);
    }

}
