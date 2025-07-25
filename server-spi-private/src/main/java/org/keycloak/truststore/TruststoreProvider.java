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

package org.keycloak.truststore;

import org.keycloak.common.enums.HostnameVerificationPolicy;
import org.keycloak.provider.Provider;

import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public interface TruststoreProvider extends Provider {

    HostnameVerificationPolicy getPolicy();

    SSLSocketFactory getSSLSocketFactory();

    KeyStore getTruststore();

    /**
     * @return root certificates from the configured truststore as a map where the key is the X500Principal of the corresponding X509Certificate
     */
    Map<X500Principal, List<X509Certificate>> getRootCertificates();

    /**
     * @return intermediate certificates from the configured truststore as a map where the key is the X500Principal of the corresponding X509Certificate
     */
    Map<X500Principal, List<X509Certificate>> getIntermediateCertificates();
}
