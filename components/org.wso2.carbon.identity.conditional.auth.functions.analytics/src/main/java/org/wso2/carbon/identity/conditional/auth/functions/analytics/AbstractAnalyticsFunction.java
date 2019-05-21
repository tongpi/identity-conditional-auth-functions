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
import org.apache.http.client.methods.HttpPost;
import org.wso2.carbon.identity.conditional.auth.functions.common.auth.AuthenticationFactory;
import org.wso2.carbon.identity.conditional.auth.functions.common.auth.AuthenticationManager;
import org.wso2.carbon.identity.conditional.auth.functions.common.auth.UsernamePasswordCredentials;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.CommonUtils;
import org.wso2.carbon.identity.event.IdentityEventException;

/**
 * Class that handle the authentication of the external analytics calls.
 */
public abstract class AbstractAnalyticsFunction {

    private static final Log LOG = LogFactory.getLog(AbstractAnalyticsFunction.class);
    protected static final String TYPE_APPLICATION_JSON = "application/json";
    protected static final String PARAM_EP_URL = "ReceiverUrl";

    protected AuthenticationFactory authenticationFactory = new AuthenticationFactory();

    /**
     * Handle the authentication of the external analytics calls.
     *
     * @param request      Request sent to the analytics engine.
     * @param tenantDomain tenant domain of the service provider.
     * @throws IdentityEventException
     */
    protected void handleAuthentication(HttpPost request, String tenantDomain) throws IdentityEventException {

        if (Boolean.parseBoolean(isBasicAuthEnabled(tenantDomain))) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("在租户：" + tenantDomain + "中的出站分析调用启用了基本身份验证");
            }
            String username = getUsername(tenantDomain);
            String password = getPassword(tenantDomain);

            AuthenticationManager authenticationManager = authenticationFactory.getAuthenticationManager("Basic");
            request.setHeader(authenticationManager.authenticate(new UsernamePasswordCredentials(username,
                    password), request));
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("租户:" + tenantDomain + "的出站分析调用未启用基本身份验证");
            }
        }
    }

    protected String getPassword(String tenantDomain) throws IdentityEventException {

        return CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl.CREDENTIAL, tenantDomain);
    }

    protected String getUsername(String tenantDomain) throws IdentityEventException {

        return CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl.USERNAME, tenantDomain);
    }

    protected String isBasicAuthEnabled(String tenantDomain) throws IdentityEventException {

        return CommonUtils.getConnectorConfig(AnalyticsEngineConfigImpl.BASIC_AUTH_ENABLED, tenantDomain);
    }
}
