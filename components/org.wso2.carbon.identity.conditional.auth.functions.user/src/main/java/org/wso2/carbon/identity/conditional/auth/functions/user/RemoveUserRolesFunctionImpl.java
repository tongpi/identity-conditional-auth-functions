/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.user;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.List;

/**
 * Function to remove given roles from the a given user.
 * The purpose is to perform role removing during dynamic authentication.
 */
public class RemoveUserRolesFunctionImpl implements RemoveUserRolesFunction {

    private static final Log LOG = LogFactory.getLog(RemoveUserRolesFunctionImpl.class);

    /**
     * {@inheritDoc}
     *
     * @param user          Authenticated user.
     * @param removingRoles Roles to be removed.
     * @return <code>true</code> If the role assigning is successfully completed. <code>false</code> for any other case.
     */
    @Override
    public boolean removeUserRoles(JsAuthenticatedUser user, List<String> removingRoles) {

        if (user == null) {
            LOG.error("用户未定义");
            return false;
        }
        if (removingRoles == null) {
            LOG.error("删除角色未定义");
            return false;
        }
        try {
            if (user.getWrapped() != null) {
                String tenantDomain = user.getWrapped().getTenantDomain();
                String userStoreDomain = user.getWrapped().getUserStoreDomain();
                String username = user.getWrapped().getUserName();
                UserRealm userRealm = Utils.getUserRealm(tenantDomain);
                if (userRealm != null) {
                    UserStoreManager userStore = Utils.getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                    userStore.updateRoleListOfUser(
                            username,
                            removingRoles.toArray(new String[0]),
                            new String[0]
                    );
                    return true;
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("在用户存储域：" + userStoreDomain + "中无法为用户: " + username + "找到用户领域");
                    }
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("无法为用户获取包装内容");
                }
            }
        } catch (UserStoreException e) {
            LOG.error("从用户获取用户时出错", e);
        } catch (FrameworkException e) {
            LOG.error("检索用户领域和用户存储管理时出错", e);
        }
        return false;
    }
}
