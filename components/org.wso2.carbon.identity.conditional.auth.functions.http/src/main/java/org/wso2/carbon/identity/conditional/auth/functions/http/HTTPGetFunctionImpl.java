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

package org.wso2.carbon.identity.conditional.auth.functions.http;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Collections;
import java.util.Map;

import static org.apache.http.HttpHeaders.ACCEPT;

/**
 * Implementation of the {@link HTTPGetFunction}
 */
public class HTTPGetFunctionImpl implements HTTPGetFunction {

    private static final Log LOG = LogFactory.getLog(HTTPGetFunctionImpl.class);
    private static final String TYPE_APPLICATION_JSON = "application/json";

    private CloseableHttpClient client;

    public HTTPGetFunctionImpl() {

        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(ConfigProvider.getInstance().getConnectionTimeout())
                .setConnectionRequestTimeout(ConfigProvider.getInstance().getConnectionRequestTimeout())
                .setSocketTimeout(ConfigProvider.getInstance().getReadTimeout())
                .build();
        client = HttpClientBuilder.create().setDefaultRequestConfig(config).build();
    }

    @Override
    public void httpGet(String epUrl, Map<String, Object> eventHandlers) {

        AsyncProcess asyncProcess = new AsyncProcess((context, asyncReturn) -> {
            JSONObject json = null;
            int responseCode;
            String outcome;

            HttpGet request = new HttpGet(epUrl);
            try {
                request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);

                try (CloseableHttpResponse response = client.execute(request)) {
                    responseCode = response.getStatusLine().getStatusCode();

                    if (responseCode == 200) {
                        outcome = Constants.OUTCOME_SUCCESS;
                        String jsonString = EntityUtils.toString(response.getEntity());
                        JSONParser parser = new JSONParser();
                        json = (JSONObject) parser.parse(jsonString);
                    } else {
                        outcome = Constants.OUTCOME_FAIL;
                    }
                }

            } catch (ConnectTimeoutException e) {
                LOG.error("等待连接" + epUrl + "时出错", e);
                outcome = Constants.OUTCOME_TIMEOUT;
            } catch (SocketTimeoutException e) {
                LOG.error("从" + epUrl + "等待数据时出错", e);
                outcome = Constants.OUTCOME_TIMEOUT;
            } catch (IOException e) {
                LOG.error("调用端点时出错。", e);
                outcome = Constants.OUTCOME_FAIL;
            } catch (ParseException e) {
                LOG.error("解析响应时出错。", e);
                outcome = Constants.OUTCOME_FAIL;
            }

            asyncReturn.accept(context, json != null ? json : Collections.emptyMap(), outcome);
        });
        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
    }
}
