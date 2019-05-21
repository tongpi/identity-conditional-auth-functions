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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.user.internal.UserFunctionsServiceHolder;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.Arrays;
import java.util.List;

public class HasAnyOfTheRolesFunctionImpl implements HasAnyOfTheRolesFunction {

    private static final Log LOG = LogFactory.getLog(HasAnyOfTheRolesFunctionImpl.class);

    @Override
    public boolean hasAnyOfTheRoles(JsAuthenticatedUser user, List<String> roleNames) {

        boolean result = false;

        String tenantDomain = user.getWrapped().getTenantDomain();
        String userStoreDomain = user.getWrapped().getUserStoreDomain();
        String username = user.getWrapped().getUserName();
        try {
            UserRealm userRealm = getUserRealm(user.getWrapped().getTenantDomain());
            if (userRealm != null) {
                UserStoreManager userStore = getUserStoreManager(tenantDomain, userRealm, userStoreDomain);
                if (userStore != null) {
                    String[] roleListOfUser = userStore.getRoleListOfUser(username);
                    result = Arrays.stream(roleListOfUser).anyMatch(roleNames::contains);
                }
            }
        } catch (FrameworkException e) {
            LOG.error("评估函数时出错", e);
        } catch (UserStoreException e) {
            LOG.error("在函数中从用户获取用户时出错", e);
        }

        return result;
    }

    private UserRealm getUserRealm(String tenantDomain) throws FrameworkException {

        UserRealm realm;
        try {
            realm = AnonymousSessionUtil.getRealmByTenantDomain(UserFunctionsServiceHolder.getInstance()
                    .getRegistryService(), UserFunctionsServiceHolder.getInstance().getRealmService(), tenantDomain);
        } catch (CarbonException e) {
            throw new FrameworkException(
                    "检索领域以获取" + tenantDomain + "以检索用户角色时发生错误", e);
        }
        return realm;
    }

    private UserStoreManager getUserStoreManager(String tenantDomain, UserRealm realm, String userDomain)
            throws FrameworkException {

        UserStoreManager userStore = null;
        try {
            if (StringUtils.isNotBlank(userDomain)) {
                userStore = realm.getUserStoreManager().getSecondaryUserStoreManager(userDomain);
            } else {
                userStore = realm.getUserStoreManager();
            }

            if (userStore == null) {
                throw new FrameworkException(
                        String.format("无效的用户存储域（给定：%s）或租户域（给定：%s）。",
                                userDomain, tenantDomain));
            }
        } catch (UserStoreException e) {
            throw new FrameworkException("从" + tenantDomain + "检索用户角色以检索用户角色时出错", e);
        }
        return userStore;
    }
}
