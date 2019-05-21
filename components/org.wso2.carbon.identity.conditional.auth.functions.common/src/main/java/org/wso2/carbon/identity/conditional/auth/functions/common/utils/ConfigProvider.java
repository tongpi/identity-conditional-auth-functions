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

package org.wso2.carbon.identity.conditional.auth.functions.common.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.HTTP_CONNECTION_REQUEST_TIMEOUT;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.HTTP_READ_TIMEOUT;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.HTTP_CONNECTION_TIMEOUT;

public class ConfigProvider {

    private static final Log LOG = LogFactory.getLog(ConfigProvider.class);

    private int connectionTimeout;
    private int readTimeout;
    private int connectionRequestTimeout;

    private static ConfigProvider instance = new ConfigProvider();

    private ConfigProvider() {

        int defaultTimeout = 5000;
        String connectionTimeoutString = IdentityUtil.getProperty(HTTP_CONNECTION_TIMEOUT);
        String readTimeoutString = IdentityUtil.getProperty(HTTP_READ_TIMEOUT);
        String connectionRequestTimeoutString = IdentityUtil.getProperty(HTTP_CONNECTION_REQUEST_TIMEOUT);

        connectionTimeout = defaultTimeout;
        readTimeout = defaultTimeout;
        connectionRequestTimeout = defaultTimeout;

        if (connectionTimeoutString != null) {
            try {
                connectionTimeout = Integer.parseInt(connectionTimeoutString);
            } catch (NumberFormatException e) {
                LOG.error("解析连接超时时出错 : " + connectionTimeoutString, e);
            }
        }
        if (readTimeoutString != null) {
            try {
                readTimeout = Integer.parseInt(readTimeoutString);
            } catch (NumberFormatException e) {
                LOG.error("解析读取超时时出错 : " + connectionTimeoutString, e);
            }
        }
        if (connectionRequestTimeoutString != null) {
            try {
                connectionRequestTimeout = Integer.parseInt(connectionRequestTimeoutString);
            } catch (NumberFormatException e) {
                LOG.error("解析连接请求超时时出错 : " + connectionTimeoutString, e);
            }
        }
    }

    public static ConfigProvider getInstance() {

        return instance;
    }

    public int getConnectionTimeout() {

        return connectionTimeout;
    }

    public int getReadTimeout() {

        return readTimeout;
    }

    public int getConnectionRequestTimeout() {

        return connectionRequestTimeout;
    }
}
