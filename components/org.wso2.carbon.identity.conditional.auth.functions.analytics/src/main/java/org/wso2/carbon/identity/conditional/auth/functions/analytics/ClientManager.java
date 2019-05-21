/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.analytics;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.impl.nio.conn.PoolingNHttpClientConnectionManager;
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor;
import org.apache.http.nio.reactor.ConnectingIOReactor;
import org.apache.http.nio.reactor.IOReactorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.analytics.internal.AnalyticsFunctionsServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLContext;

/**
 * Class to retrieve the HTTP Clients.
 */
public class ClientManager {

    private static final Log LOG = LogFactory.getLog(ClientManager.class);

    private static ClientManager instance = new ClientManager();

    private static Map<Integer, CloseableHttpAsyncClient> clientMap = new HashMap<>();

    public static ClientManager getInstance() {

        return instance;
    }

    private ClientManager() {

    }

    /**
     * Get HTTPClient properly configured with tenant configurations.
     *
     * @param tenantDomain tenant domain of the service provider.
     * @return HttpClient
     */
    public CloseableHttpAsyncClient getClient(String tenantDomain) throws FrameworkException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        CloseableHttpAsyncClient client = clientMap.get(tenantId);

        if (client == null) {

            PoolingNHttpClientConnectionManager poolingHttpClientConnectionManager = createPoolingConnectionManager();

            RequestConfig config = createRequestConfig(tenantDomain);

            HttpAsyncClientBuilder httpClientBuilder = HttpAsyncClients.custom().setDefaultRequestConfig(config);

            addSslContext(httpClientBuilder, tenantDomain);
            httpClientBuilder.setConnectionManager(poolingHttpClientConnectionManager);

            client = httpClientBuilder.build();
            client.start();
            clientMap.put(tenantId, client);
        }

        return client;
    }

    private RequestConfig createRequestConfig(String tenantDomain) {

        int defaultTimeout = 5000;
        String connectionTimeoutString = null;
        String readTimeoutString = null;
        String connectionRequestTimeoutString = null;
        try {
            connectionTimeoutString = CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl
                    .HTTP_CONNECTION_TIMEOUT, tenantDomain);
        } catch (IdentityEventException e) {
            // Ignore. If there was error while getting the property, continue with default value.
        }
        try {
            readTimeoutString = CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl
                    .HTTP_READ_TIMEOUT, tenantDomain);
        } catch (IdentityEventException e) {
            // Ignore. If there was error while getting the property, continue with default value.
        }
        try {
            connectionRequestTimeoutString = CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl
                    .HTTP_CONNECTION_REQUEST_TIMEOUT, tenantDomain);
        } catch (IdentityEventException e) {
            // Ignore. If there was error while getting the property, continue with default value.
        }

        int connectionTimeout = defaultTimeout;
        int readTimeout = defaultTimeout;
        int connectionRequestTimeout = defaultTimeout;

        if (connectionTimeoutString != null) {
            try {
                connectionTimeout = Integer.parseInt(connectionTimeoutString);
            } catch (NumberFormatException e) {
                LOG.error("解析连接超时时出错：" + connectionTimeoutString, e);
            }
        }
        if (readTimeoutString != null) {
            try {
                readTimeout = Integer.parseInt(readTimeoutString);
            } catch (NumberFormatException e) {
                LOG.error("解析读取超时时出错：" + connectionTimeoutString, e);
            }
        }
        if (connectionRequestTimeoutString != null) {
            try {
                connectionRequestTimeout = Integer.parseInt(connectionRequestTimeoutString);
            } catch (NumberFormatException e) {
                LOG.error("解析连接请求超时时出错：" + connectionTimeoutString, e);
            }
        }

        return RequestConfig.custom()
                .setConnectTimeout(connectionTimeout)
                .setConnectionRequestTimeout(connectionRequestTimeout)
                .setSocketTimeout(readTimeout)
                .build();
    }

    private PoolingNHttpClientConnectionManager createPoolingConnectionManager() throws FrameworkException {

        String maxConnectionsString = IdentityUtil.getProperty(Constants.CONNECTION_POOL_MAX_CONNECTIONS);
        String maxConnectionsPerRouteString = IdentityUtil.getProperty(Constants
                .CONNECTION_POOL_MAX_CONNECTIONS_PER_ROUTE);
        int defaultMaxConnections = 20;
        int maxConnections = defaultMaxConnections;
        int maxConnectionsPerRoute = defaultMaxConnections;
        try {
            maxConnections = Integer.parseInt(maxConnectionsString);
        } catch (NumberFormatException e) {
            // Ignore. Default value is used.
        }
        try {
            maxConnectionsPerRoute = Integer.parseInt(maxConnectionsPerRouteString);
        } catch (NumberFormatException e) {
            // Ignore. Default value is used.
        }

        ConnectingIOReactor ioReactor;
        try {
            ioReactor = new DefaultConnectingIOReactor();
        } catch (IOReactorException e) {
            throw new FrameworkException("创建ConnectingIOReactor时出错", e);
        }
        PoolingNHttpClientConnectionManager poolingHttpClientConnectionManager = new
                PoolingNHttpClientConnectionManager(ioReactor);
        // Increase max total connection to 50
        poolingHttpClientConnectionManager.setMaxTotal(maxConnections);
        // Increase default max connection per route to 50
        poolingHttpClientConnectionManager.setDefaultMaxPerRoute(maxConnectionsPerRoute);
        return poolingHttpClientConnectionManager;
    }

    public void closeClient(int tenantId) throws IOException {

        CloseableHttpAsyncClient client = clientMap.get(tenantId);

        if (client != null) {
            clientMap.remove(tenantId);
            client.close();
        }
    }

    private void addSslContext(HttpAsyncClientBuilder builder, String tenantDomain) {

        try {
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(AnalyticsFunctionsServiceHolder.getInstance().getTrustStore())
                    .build();

            String hostnameVerifierConfig = CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl
                    .HOSTNAME_VERIFIER, tenantDomain);
            X509HostnameVerifier hostnameVerifier;
            if (AnalyticsEngineConfigImpl.HOSTNAME_VERIFIER_STRICT.equalsIgnoreCase(hostnameVerifierConfig)) {
                hostnameVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
            } else if (AnalyticsEngineConfigImpl.HOSTNAME_VERIFIER_ALLOW_ALL.equalsIgnoreCase(hostnameVerifierConfig)) {
                hostnameVerifier = SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
            } else {
                hostnameVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
            }

            builder.setSSLContext(sslContext);
            builder.setHostnameVerifier(hostnameVerifier);
        } catch (Exception e) {
            LOG.error("在租户域：" + tenantDomain + "中的分析端点调用创建ssl上下文时出错", e);
        }
    }

}
