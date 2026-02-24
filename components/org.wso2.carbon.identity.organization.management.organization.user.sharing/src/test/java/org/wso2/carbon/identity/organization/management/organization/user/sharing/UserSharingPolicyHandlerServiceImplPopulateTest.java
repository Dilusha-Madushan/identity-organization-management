/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.organization.management.organization.user.sharing;

import org.mockito.InjectMocks;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SharedType;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserSharingMgtClientException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.internal.OrganizationUserSharingDataHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.GeneralUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.GeneralUserUnshareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.RoleWithAudienceDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.SelectiveUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.SelectiveUserShareOrgDetailsDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.SelectiveUserUnshareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.usercriteria.UserCriteriaType;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.usercriteria.UserIdList;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.Utils;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.ResourceSharingPolicyHandlerService;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.PolicyEnum;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.testng.Assert.assertThrows;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.ORGANIZATION_AUDIENCE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.ORG_1_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.ORG_1_NAME;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.ORG_2_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.ORG_3_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.ORG_ROLE_1_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.ORG_ROLE_1_NAME;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.ORG_SUPER_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.TENANT_DOMAIN;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.TENANT_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.TestUserSharingConstants.USER_1_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.CLAIM_MANAGED_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_IDS;

/**
 * Unit tests for the async populate methods of UserSharingPolicyHandlerServiceImpl.
 * Covers populateSelectiveUserShare, populateGeneralUserShare,
 * populateSelectiveUserUnshare, and populateGeneralUserUnshare.
 */
public class UserSharingPolicyHandlerServiceImplPopulateTest {

    private static final String ADMIN_USER_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    private static final String ADMIN_USERNAME = "admin";

    @InjectMocks
    private UserSharingPolicyHandlerServiceImpl userSharingPolicyHandlerService;

    private MockedStatic<UserSharingPolicyHandlerServiceImpl> userSharingPolicyHandlerServiceMockStatic;
    private MockedStatic<OrganizationUserSharingDataHolder> dataHolderMockStatic;
    private MockedStatic<Utils> utilsMockedStatic;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<UserCoreUtil> userCoreUtilMockedStatic;
    private MockedStatic<PrivilegedCarbonContext> privilegedCarbonContextMockStatic;

    @BeforeMethod
    public void setUp() {

        openMocks(this);
        userSharingPolicyHandlerServiceMockStatic = mockStatic(UserSharingPolicyHandlerServiceImpl.class);
        dataHolderMockStatic = mockStatic(OrganizationUserSharingDataHolder.class);
        utilsMockedStatic = mockStatic(Utils.class);
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        userCoreUtilMockedStatic = mockStatic(UserCoreUtil.class);
        privilegedCarbonContextMockStatic = mockStatic(PrivilegedCarbonContext.class);
    }

    @AfterMethod
    public void tearDown() {

        userSharingPolicyHandlerServiceMockStatic.close();
        dataHolderMockStatic.close();
        utilsMockedStatic.close();
        identityTenantUtilMockedStatic.close();
        userCoreUtilMockedStatic.close();
        privilegedCarbonContextMockStatic.close();
    }

    @DataProvider(name = "selectiveShareValidationDataProvider")
    public Object[][] selectiveShareValidationDataProvider() {

        return new Object[][]{
                {null},
                {buildSelectiveShareDO(null, buildValidOrgDetailsList())},
                {buildSelectiveShareDO(
                        Collections.singletonMap("wrongKey", new UserIdList(Collections.singletonList(USER_1_ID))),
                        buildValidOrgDetailsList())},
                {buildSelectiveShareDO(
                        Collections.singletonMap(USER_IDS, null),
                        buildValidOrgDetailsList())},
                {buildSelectiveShareDO(
                        buildValidUserCriteria(), null)},
                {buildSelectiveShareDO(
                        buildValidUserCriteria(),
                        Collections.singletonList(buildOrgDetails(null, PolicyEnum.SELECTED_ORG_ONLY,
                                Collections.emptyList())))},
                {buildSelectiveShareDO(
                        buildValidUserCriteria(),
                        Collections.singletonList(buildOrgDetails(ORG_1_ID, null, Collections.emptyList())))},
                {buildSelectiveShareDO(
                        buildValidUserCriteria(),
                        Collections.singletonList(buildOrgDetails(ORG_1_ID, PolicyEnum.SELECTED_ORG_ONLY, null)))},
                {buildSelectiveShareDO(
                        buildValidUserCriteria(),
                        Collections.singletonList(buildOrgDetails(ORG_1_ID, PolicyEnum.SELECTED_ORG_ONLY,
                                Collections.singletonList(buildRole(null, "App1", "application")))))},
                {buildSelectiveShareDO(
                        buildValidUserCriteria(),
                        Collections.singletonList(buildOrgDetails(ORG_1_ID, PolicyEnum.SELECTED_ORG_ONLY,
                                Collections.singletonList(buildRole("role1", null, "application")))))},
                {buildSelectiveShareDO(
                        buildValidUserCriteria(),
                        Collections.singletonList(buildOrgDetails(ORG_1_ID, PolicyEnum.SELECTED_ORG_ONLY,
                                Collections.singletonList(buildRole("role1", "App1", null)))))}
        };
    }

    @Test(dataProvider = "selectiveShareValidationDataProvider")
    public void testPopulateSelectiveUserShare_ThrowsOnInvalidInput(SelectiveUserShareDO shareDO) {

        assertThrows(UserSharingMgtClientException.class,
                () -> userSharingPolicyHandlerService.populateSelectiveUserShare(shareDO));
    }


    @Test
    public void testPopulateSelectiveUserShare_SharesResidentUserAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);
        ResourceSharingPolicyHandlerService mockResourceSharingService =
                mock(ResourceSharingPolicyHandlerService.class);
        when(dataHolder.getResourceSharingPolicyHandlerService()).thenReturn(mockResourceSharingService);

        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, false))
                .thenReturn(Collections.singletonList(ORG_1_ID));
        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(new HashMap<>());
        when(mockOrgUserSharingService.hasUserAssociations(USER_1_ID, ORG_SUPER_ID)).thenReturn(false);
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_1_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_1_ID));

        SelectiveUserShareDO shareDO = buildSelectiveShareDO(
                buildValidUserCriteria(),
                Collections.singletonList(
                        buildOrgDetails(ORG_1_ID, PolicyEnum.SELECTED_ORG_ONLY, Collections.emptyList())));

        userSharingPolicyHandlerService.populateSelectiveUserShare(shareDO);

        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_1_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
    }


    @Test
    public void testPopulateSelectiveUserShare_SkipsNonResidentUserAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);

        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, false))
                .thenReturn(Collections.singletonList(ORG_1_ID));
        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(Collections.singletonMap(CLAIM_MANAGED_ORGANIZATION, ORG_SUPER_ID));

        SelectiveUserShareDO shareDO = buildSelectiveShareDO(
                buildValidUserCriteria(),
                Collections.singletonList(
                        buildOrgDetails(ORG_1_ID, PolicyEnum.SELECTED_ORG_ONLY, Collections.emptyList())));

        userSharingPolicyHandlerService.populateSelectiveUserShare(shareDO);

        verify(mockOrgUserSharingService, after(1000).never())
                .shareOrganizationUser(anyString(), anyString(), anyString(), any());
    }


    @Test
    public void testPopulateSelectiveUserShare_SkipsNonExistingUserAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);

        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, false))
                .thenReturn(Collections.singletonList(ORG_1_ID));
        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(false);

        SelectiveUserShareDO shareDO = buildSelectiveShareDO(
                buildValidUserCriteria(),
                Collections.singletonList(
                        buildOrgDetails(ORG_1_ID, PolicyEnum.SELECTED_ORG_ONLY, Collections.emptyList())));

        userSharingPolicyHandlerService.populateSelectiveUserShare(shareDO);

        verify(mockOrgUserSharingService, after(1000).never())
                .shareOrganizationUser(anyString(), anyString(), anyString(), any());
    }

    @Test
    public void testPopulateSelectiveUserShare_TakesUpdatePathWhenUserAlreadySharedAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);

        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, false))
                .thenReturn(Collections.singletonList(ORG_1_ID));
        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(new HashMap<>());
        when(mockOrgUserSharingService.hasUserAssociations(USER_1_ID, ORG_SUPER_ID)).thenReturn(true);

        SelectiveUserShareDO shareDO = buildSelectiveShareDO(
                buildValidUserCriteria(),
                Collections.singletonList(
                        buildOrgDetails(ORG_1_ID, PolicyEnum.SELECTED_ORG_ONLY, Collections.emptyList())));

        userSharingPolicyHandlerService.populateSelectiveUserShare(shareDO);

        verify(mockOrgUserSharingService, timeout(3000)).hasUserAssociations(USER_1_ID, ORG_SUPER_ID);
        verify(mockOrgUserSharingService, after(1000).never())
                .shareOrganizationUser(anyString(), anyString(), anyString(), any());
    }

    @Test
    public void testPopulateSelectiveUserShare_SharesWithAllExistingChildrenPolicyAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);
        ResourceSharingPolicyHandlerService mockResourceSharingService =
                mock(ResourceSharingPolicyHandlerService.class);
        when(dataHolder.getResourceSharingPolicyHandlerService()).thenReturn(mockResourceSharingService);

        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, false))
                .thenReturn(Collections.singletonList(ORG_1_ID));
        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(new HashMap<>());
        when(mockOrgUserSharingService.hasUserAssociations(USER_1_ID, ORG_SUPER_ID)).thenReturn(false);
        when(mockOrgManager.getChildOrganizationsIds(ORG_1_ID, true))
                .thenReturn(Arrays.asList(ORG_2_ID, ORG_3_ID));
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_1_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_1_ID));
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_2_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_2_ID));
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_3_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_3_ID));

        SelectiveUserShareDO shareDO = buildSelectiveShareDO(
                buildValidUserCriteria(),
                Collections.singletonList(buildOrgDetails(ORG_1_ID,
                        PolicyEnum.SELECTED_ORG_WITH_ALL_EXISTING_CHILDREN_ONLY, Collections.emptyList())));

        userSharingPolicyHandlerService.populateSelectiveUserShare(shareDO);

        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_1_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_2_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_3_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
    }

    @Test
    public void testPopulateSelectiveUserShare_SharesWithExistingImmediateChildrenPolicyAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);
        ResourceSharingPolicyHandlerService mockResourceSharingService =
                mock(ResourceSharingPolicyHandlerService.class);
        when(dataHolder.getResourceSharingPolicyHandlerService()).thenReturn(mockResourceSharingService);

        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, false))
                .thenReturn(Collections.singletonList(ORG_1_ID));
        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(new HashMap<>());
        when(mockOrgUserSharingService.hasUserAssociations(USER_1_ID, ORG_SUPER_ID)).thenReturn(false);
        when(mockOrgManager.getChildOrganizationsIds(ORG_1_ID, false))
                .thenReturn(Collections.singletonList(ORG_2_ID));
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_1_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_1_ID));
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_2_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_2_ID));

        SelectiveUserShareDO shareDO = buildSelectiveShareDO(
                buildValidUserCriteria(),
                Collections.singletonList(buildOrgDetails(ORG_1_ID,
                        PolicyEnum.SELECTED_ORG_WITH_EXISTING_IMMEDIATE_CHILDREN_ONLY, Collections.emptyList())));

        userSharingPolicyHandlerService.populateSelectiveUserShare(shareDO);

        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_1_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_2_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
    }

    @Test
    public void testPopulateSelectiveUserShare_SharesResidentUserWithRolesAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);
        ResourceSharingPolicyHandlerService mockResourceSharingService =
                mock(ResourceSharingPolicyHandlerService.class);
        when(dataHolder.getResourceSharingPolicyHandlerService()).thenReturn(mockResourceSharingService);
        RoleManagementService mockRoleManagementService = mock(RoleManagementService.class);
        when(dataHolder.getRoleManagementService()).thenReturn(mockRoleManagementService);
        when(mockRoleManagementService.getRoleIdByName(ORG_ROLE_1_NAME, ORGANIZATION_AUDIENCE,
                ORG_SUPER_ID, TENANT_DOMAIN)).thenReturn(ORG_ROLE_1_ID);

        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, false))
                .thenReturn(Collections.singletonList(ORG_1_ID));
        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(new HashMap<>());
        when(mockOrgUserSharingService.hasUserAssociations(USER_1_ID, ORG_SUPER_ID)).thenReturn(false);
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_1_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_1_ID));

        SelectiveUserShareDO shareDO = buildSelectiveShareDO(
                buildValidUserCriteria(),
                Collections.singletonList(buildOrgDetails(ORG_1_ID, PolicyEnum.SELECTED_ORG_ONLY,
                        Collections.singletonList(buildRole(ORG_ROLE_1_NAME, ORG_1_NAME, ORGANIZATION_AUDIENCE)))));

        userSharingPolicyHandlerService.populateSelectiveUserShare(shareDO);

        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_1_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
        verify(mockRoleManagementService, timeout(3000))
                .getRoleIdByName(ORG_ROLE_1_NAME, ORGANIZATION_AUDIENCE, ORG_SUPER_ID, TENANT_DOMAIN);
    }

    @DataProvider(name = "generalShareValidationDataProvider")
    public Object[][] generalShareValidationDataProvider() {

        return new Object[][]{
                {null},                                                      // Null share DO.
                {buildGeneralShareDO(null, PolicyEnum.ALL_EXISTING_ORGS_ONLY,
                        Collections.emptyList())},                           // Null userCriteria.
                {buildGeneralShareDO(Collections.singletonMap("wrongKey",    // Missing USER_IDS key.
                        new UserIdList(Collections.singletonList(USER_1_ID))),
                        PolicyEnum.ALL_EXISTING_ORGS_ONLY, Collections.emptyList())},
                {buildGeneralShareDO(Collections.singletonMap(USER_IDS, null), // Null USER_IDS value.
                        PolicyEnum.ALL_EXISTING_ORGS_ONLY, Collections.emptyList())},
                {buildGeneralShareDO(buildValidUserCriteria(), null,         // Null policy.
                        Collections.emptyList())},
                {buildGeneralShareDO(buildValidUserCriteria(),               // Null roles list.
                        PolicyEnum.ALL_EXISTING_ORGS_ONLY, null)},
                {buildGeneralShareDO(buildValidUserCriteria(),               // Role with null role name.
                        PolicyEnum.ALL_EXISTING_ORGS_ONLY,
                        Collections.singletonList(buildRole(null, "App1", "application")))},
                {buildGeneralShareDO(buildValidUserCriteria(),               // Role with null audience name.
                        PolicyEnum.ALL_EXISTING_ORGS_ONLY,
                        Collections.singletonList(buildRole("role1", null, "application")))},
                {buildGeneralShareDO(buildValidUserCriteria(),               // Role with null audience type.
                        PolicyEnum.ALL_EXISTING_ORGS_ONLY,
                        Collections.singletonList(buildRole("role1", "App1", null)))}
        };
    }

    @Test(dataProvider = "generalShareValidationDataProvider")
    public void testPopulateGeneralUserShare_ThrowsOnInvalidInput(GeneralUserShareDO shareDO) {

        assertThrows(UserSharingMgtClientException.class,
                () -> userSharingPolicyHandlerService.populateGeneralUserShare(shareDO));
    }

    @Test
    public void testPopulateGeneralUserShare_SharesResidentUserAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);
        ResourceSharingPolicyHandlerService mockResourceSharingService =
                mock(ResourceSharingPolicyHandlerService.class);
        when(dataHolder.getResourceSharingPolicyHandlerService()).thenReturn(mockResourceSharingService);

        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, true))
                .thenReturn(Arrays.asList(ORG_1_ID, ORG_2_ID, ORG_3_ID));

        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(new HashMap<>());
        when(mockOrgUserSharingService.hasUserAssociations(USER_1_ID, ORG_SUPER_ID)).thenReturn(false);
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_1_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_1_ID));
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_2_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_2_ID));
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_3_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_3_ID));

        GeneralUserShareDO shareDO = buildGeneralShareDO(
                buildValidUserCriteria(), PolicyEnum.ALL_EXISTING_ORGS_ONLY, Collections.emptyList());

        userSharingPolicyHandlerService.populateGeneralUserShare(shareDO);

        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_1_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_2_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_3_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
    }

    @Test
    public void testPopulateGeneralUserShare_SharesWithImmediateOrgsOnlyAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);
        ResourceSharingPolicyHandlerService mockResourceSharingService =
                mock(ResourceSharingPolicyHandlerService.class);
        when(dataHolder.getResourceSharingPolicyHandlerService()).thenReturn(mockResourceSharingService);

        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, false))
                .thenReturn(Arrays.asList(ORG_1_ID, ORG_2_ID));

        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(new HashMap<>());
        when(mockOrgUserSharingService.hasUserAssociations(USER_1_ID, ORG_SUPER_ID)).thenReturn(false);
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_1_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_1_ID));
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_2_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_2_ID));

        GeneralUserShareDO shareDO = buildGeneralShareDO(
                buildValidUserCriteria(), PolicyEnum.IMMEDIATE_EXISTING_ORGS_ONLY, Collections.emptyList());

        userSharingPolicyHandlerService.populateGeneralUserShare(shareDO);

        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_1_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_2_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
    }

    @Test
    public void testPopulateGeneralUserShare_DoesNotShareForNoSharingPolicyAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);

        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);

        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(new HashMap<>());
        when(mockOrgUserSharingService.hasUserAssociations(USER_1_ID, ORG_SUPER_ID)).thenReturn(false);

        GeneralUserShareDO shareDO = buildGeneralShareDO(
                buildValidUserCriteria(), PolicyEnum.NO_SHARING, Collections.emptyList());

        userSharingPolicyHandlerService.populateGeneralUserShare(shareDO);

        verify(mockOrgUserSharingService, after(1000).never())
                .shareOrganizationUser(anyString(), anyString(), anyString(), any());
    }

    @Test
    public void testPopulateGeneralUserShare_SkipsNonResidentUserAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);

        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, true))
                .thenReturn(Arrays.asList(ORG_1_ID, ORG_2_ID, ORG_3_ID));

        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(Collections.singletonMap(CLAIM_MANAGED_ORGANIZATION, ORG_SUPER_ID));

        GeneralUserShareDO shareDO = buildGeneralShareDO(
                buildValidUserCriteria(), PolicyEnum.ALL_EXISTING_ORGS_ONLY, Collections.emptyList());

        userSharingPolicyHandlerService.populateGeneralUserShare(shareDO);

        verify(mockOrgUserSharingService, after(1000).never())
                .shareOrganizationUser(anyString(), anyString(), anyString(), any());
    }

    @Test
    public void testPopulateGeneralUserShare_SkipsNonExistingUserAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);

        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);

        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(false);

        GeneralUserShareDO shareDO = buildGeneralShareDO(
                buildValidUserCriteria(), PolicyEnum.ALL_EXISTING_ORGS_ONLY, Collections.emptyList());

        userSharingPolicyHandlerService.populateGeneralUserShare(shareDO);

        verify(mockOrgUserSharingService, after(1000).never())
                .shareOrganizationUser(anyString(), anyString(), anyString(), any());
    }

    @Test
    public void testPopulateGeneralUserShare_TakesUpdatePathWhenUserAlreadySharedAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);

        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);

        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(new HashMap<>());
        when(mockOrgUserSharingService.hasUserAssociations(USER_1_ID, ORG_SUPER_ID)).thenReturn(true);

        GeneralUserShareDO shareDO = buildGeneralShareDO(
                buildValidUserCriteria(), PolicyEnum.ALL_EXISTING_ORGS_ONLY, Collections.emptyList());

        userSharingPolicyHandlerService.populateGeneralUserShare(shareDO);

        verify(mockOrgUserSharingService, timeout(3000)).hasUserAssociations(USER_1_ID, ORG_SUPER_ID);
        verify(mockOrgUserSharingService, after(1000).never())
                .shareOrganizationUser(anyString(), anyString(), anyString(), any());
    }

    @Test
    public void testPopulateGeneralUserShare_SharesResidentUserWithRolesAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUserId()).thenReturn(ADMIN_USER_ID);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        OrganizationManager mockOrgManager = mock(OrganizationManager.class);
        when(dataHolder.getOrganizationManager()).thenReturn(mockOrgManager);
        ResourceSharingPolicyHandlerService mockResourceSharingService =
                mock(ResourceSharingPolicyHandlerService.class);
        when(dataHolder.getResourceSharingPolicyHandlerService()).thenReturn(mockResourceSharingService);

        when(mockOrgManager.resolveTenantDomain(ORG_SUPER_ID)).thenReturn(TENANT_DOMAIN);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN))
                .thenReturn(TENANT_ID);
        RoleManagementService mockRoleManagementService = mock(RoleManagementService.class);
        when(dataHolder.getRoleManagementService()).thenReturn(mockRoleManagementService);
        when(mockRoleManagementService.getRoleIdByName(ORG_ROLE_1_NAME, ORGANIZATION_AUDIENCE,
                ORG_SUPER_ID, TENANT_DOMAIN)).thenReturn(ORG_ROLE_1_ID);

        when(mockOrgManager.getChildOrganizationsIds(ORG_SUPER_ID, true))
                .thenReturn(Collections.singletonList(ORG_1_ID));

        RealmService mockRealmService = mock(RealmService.class);
        when(dataHolder.getRealmService()).thenReturn(mockRealmService);
        UserRealm mockUserRealm = mock(UserRealm.class);
        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);
        AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.isExistingUserWithID(USER_1_ID)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValuesWithID(anyString(), any(String[].class), any()))
                .thenReturn(new HashMap<>());
        when(mockOrgUserSharingService.hasUserAssociations(USER_1_ID, ORG_SUPER_ID)).thenReturn(false);
        when(mockOrgUserSharingService.getUserAssociationOfAssociatedUserByOrgId(USER_1_ID, ORG_1_ID))
                .thenReturn(createUserAssociation(USER_1_ID, ORG_1_ID));

        GeneralUserShareDO shareDO = buildGeneralShareDO(
                buildValidUserCriteria(),
                PolicyEnum.ALL_EXISTING_ORGS_ONLY,
                Collections.singletonList(buildRole(ORG_ROLE_1_NAME, ORG_1_NAME, ORGANIZATION_AUDIENCE)));

        userSharingPolicyHandlerService.populateGeneralUserShare(shareDO);

        verify(mockRoleManagementService)
                .getRoleIdByName(ORG_ROLE_1_NAME, ORGANIZATION_AUDIENCE, ORG_SUPER_ID, TENANT_DOMAIN);
        verify(mockOrgUserSharingService, timeout(3000))
                .shareOrganizationUser(ORG_1_ID, USER_1_ID, ORG_SUPER_ID, SharedType.SHARED);
    }

    @DataProvider(name = "selectiveUnshareValidationDataProvider")
    public Object[][] selectiveUnshareValidationDataProvider() {

        return new Object[][]{
                {null},                                                      // Null unshare DO.
                {buildSelectiveUnshareDO(null, buildValidOrgIdList())},      // Null userCriteria.
                {buildSelectiveUnshareDO(Collections.singletonMap("wrongKey", // Missing USER_IDS key.
                        new UserIdList(Collections.singletonList(USER_1_ID))),
                        buildValidOrgIdList())},
                {buildSelectiveUnshareDO(Collections.singletonMap(USER_IDS, null), // Null USER_IDS value.
                        buildValidOrgIdList())},
                {buildSelectiveUnshareDO(buildValidUserCriteria(), null)},   // Null organizations list.
                {buildSelectiveUnshareDO(buildValidUserCriteria(),           // Null org ID in list.
                        Collections.singletonList(null))}
        };
    }

    @Test(dataProvider = "selectiveUnshareValidationDataProvider")
    public void testPopulateSelectiveUserUnshare_ThrowsOnInvalidInput(SelectiveUserUnshareDO unshareDO) {

        assertThrows(UserSharingMgtClientException.class,
                () -> userSharingPolicyHandlerService.populateSelectiveUserUnshare(unshareDO));
    }

    @Test
    public void testPopulateSelectiveUserUnshare_UnshareAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        ResourceSharingPolicyHandlerService mockResourceSharingService =
                mock(ResourceSharingPolicyHandlerService.class);
        when(dataHolder.getResourceSharingPolicyHandlerService()).thenReturn(mockResourceSharingService);

        SelectiveUserUnshareDO unshareDO = buildSelectiveUnshareDO(
                buildValidUserCriteria(), Collections.singletonList(ORG_1_ID));

        userSharingPolicyHandlerService.populateSelectiveUserUnshare(unshareDO);

        verify(mockOrgUserSharingService, timeout(3000))
                .unshareOrganizationUserInSharedOrganization(USER_1_ID, ORG_1_ID);
    }

    @Test
    public void testPopulateSelectiveUserUnshare_UnshareFromMultipleOrgsAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        ResourceSharingPolicyHandlerService mockResourceSharingService =
                mock(ResourceSharingPolicyHandlerService.class);
        when(dataHolder.getResourceSharingPolicyHandlerService()).thenReturn(mockResourceSharingService);

        SelectiveUserUnshareDO unshareDO = buildSelectiveUnshareDO(
                buildValidUserCriteria(), Arrays.asList(ORG_1_ID, ORG_2_ID));

        userSharingPolicyHandlerService.populateSelectiveUserUnshare(unshareDO);

        verify(mockOrgUserSharingService, timeout(3000))
                .unshareOrganizationUserInSharedOrganization(USER_1_ID, ORG_1_ID);
        verify(mockOrgUserSharingService, timeout(3000))
                .unshareOrganizationUserInSharedOrganization(USER_1_ID, ORG_2_ID);
    }

    @DataProvider(name = "generalUnshareValidationDataProvider")
    public Object[][] generalUnshareValidationDataProvider() {

        return new Object[][]{
                {null},                                              // Null unshare DO.
                {buildGeneralUnshareDO(null)},                       // Null userCriteria.
                {buildGeneralUnshareDO(Collections.singletonMap("wrongKey",   // Missing USER_IDS key.
                        new UserIdList(Collections.singletonList(USER_1_ID))))},
                {buildGeneralUnshareDO(Collections.singletonMap(USER_IDS, null))} // Null USER_IDS value.
        };
    }

    @Test(dataProvider = "generalUnshareValidationDataProvider")
    public void testPopulateGeneralUserUnshare_ThrowsOnInvalidInput(GeneralUserUnshareDO unshareDO) {

        assertThrows(UserSharingMgtClientException.class,
                () -> userSharingPolicyHandlerService.populateGeneralUserUnshare(unshareDO));
    }

    @Test
    public void testPopulateGeneralUserUnshare_UnshareAsync() throws Exception {

        utilsMockedStatic.when(Utils::getOrganizationId).thenReturn(ORG_SUPER_ID);

        PrivilegedCarbonContext mockCarbonContext = mock(PrivilegedCarbonContext.class);
        privilegedCarbonContextMockStatic.when(
                PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockCarbonContext);
        when(mockCarbonContext.getUsername()).thenReturn(ADMIN_USERNAME);
        when(mockCarbonContext.getTenantId()).thenReturn(TENANT_ID);
        when(mockCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        OrganizationUserSharingDataHolder dataHolder = mock(OrganizationUserSharingDataHolder.class);
        when(OrganizationUserSharingDataHolder.getInstance()).thenReturn(dataHolder);
        OrganizationUserSharingService mockOrgUserSharingService = mock(OrganizationUserSharingService.class);
        when(dataHolder.getOrganizationUserSharingService()).thenReturn(mockOrgUserSharingService);
        ResourceSharingPolicyHandlerService mockResourceSharingService =
                mock(ResourceSharingPolicyHandlerService.class);
        when(dataHolder.getResourceSharingPolicyHandlerService()).thenReturn(mockResourceSharingService);

        GeneralUserUnshareDO unshareDO = buildGeneralUnshareDO(buildValidUserCriteria());

        userSharingPolicyHandlerService.populateGeneralUserUnshare(unshareDO);

        verify(mockOrgUserSharingService, timeout(3000))
                .unshareOrganizationUsers(USER_1_ID, ORG_SUPER_ID);
    }

    private Map<String, UserIdList> buildValidUserCriteria() {

        return Collections.singletonMap(USER_IDS, new UserIdList(Collections.singletonList(USER_1_ID)));
    }

    private List<SelectiveUserShareOrgDetailsDO> buildValidOrgDetailsList() {

        return Collections.singletonList(
                buildOrgDetails(ORG_1_ID, PolicyEnum.SELECTED_ORG_ONLY, Collections.emptyList()));
    }

    private List<String> buildValidOrgIdList() {

        return Collections.singletonList(ORG_1_ID);
    }

    @SuppressWarnings("unchecked")
    private SelectiveUserShareDO buildSelectiveShareDO(Map<String, ?> userCriteria,
                                                       List<SelectiveUserShareOrgDetailsDO> organizations) {

        SelectiveUserShareDO shareDO = new SelectiveUserShareDO();
        shareDO.setUserCriteria((Map<String, UserCriteriaType>) userCriteria);
        shareDO.setOrganizations(organizations);
        return shareDO;
    }

    @SuppressWarnings("unchecked")
    private GeneralUserShareDO buildGeneralShareDO(Map<String, ?> userCriteria, PolicyEnum policy,
                                                   List<RoleWithAudienceDO> roles) {

        GeneralUserShareDO shareDO = new GeneralUserShareDO();
        shareDO.setUserCriteria((Map<String, UserCriteriaType>) userCriteria);
        shareDO.setPolicy(policy);
        shareDO.setRoles(roles);
        return shareDO;
    }

    @SuppressWarnings("unchecked")
    private SelectiveUserUnshareDO buildSelectiveUnshareDO(Map<String, ?> userCriteria,
                                                           List<String> organizations) {

        SelectiveUserUnshareDO unshareDO = new SelectiveUserUnshareDO();
        unshareDO.setUserCriteria((Map<String, UserCriteriaType>) userCriteria);
        unshareDO.setOrganizations(organizations);
        return unshareDO;
    }

    @SuppressWarnings("unchecked")
    private GeneralUserUnshareDO buildGeneralUnshareDO(Map<String, ?> userCriteria) {

        GeneralUserUnshareDO unshareDO = new GeneralUserUnshareDO();
        unshareDO.setUserCriteria((Map<String, UserCriteriaType>) userCriteria);
        return unshareDO;
    }

    private SelectiveUserShareOrgDetailsDO buildOrgDetails(String organizationId, PolicyEnum policy,
                                                           List<RoleWithAudienceDO> roles) {

        SelectiveUserShareOrgDetailsDO orgDetails = new SelectiveUserShareOrgDetailsDO();
        orgDetails.setOrganizationId(organizationId);
        orgDetails.setPolicy(policy);
        orgDetails.setRoles(roles);
        return orgDetails;
    }

    private RoleWithAudienceDO buildRole(String roleName, String audienceName, String audienceType) {

        RoleWithAudienceDO role = new RoleWithAudienceDO();
        role.setRoleName(roleName);
        role.setAudienceName(audienceName);
        role.setAudienceType(audienceType);
        return role;
    }

    private UserAssociation createUserAssociation(String userId, String organizationId) {

        UserAssociation userAssociation = new UserAssociation();
        userAssociation.setUserId(userId);
        userAssociation.setOrganizationId(organizationId);
        userAssociation.setSharedType(SharedType.SHARED);
        return userAssociation;
    }
}
