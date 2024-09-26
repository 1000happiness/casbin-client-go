package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"

	"github.com/1000happiness/casbin-client-go/config"
	pb "github.com/1000happiness/casbin-client-go/proto"
	"github.com/1000happiness/casbin-client-go/util"
)

type CasbinHttpClient struct {
	hc http.Client

	baseUrl string
	name    string
	token   string

	originDomain    string
	domain          string
	originApprovers []string
	approvers       []string
	originMessage   string
	message         string

	config *config.CasbinConfig
}

func NewCasbinHttpClient(baseUrl string, name string, domain string, token string, approvers []string, message string) (*CasbinHttpClient, error) {
	hc := http.Client{}

	c := &CasbinHttpClient{
		hc:              hc,
		baseUrl:         baseUrl,
		name:            name,
		token:           token,
		originDomain:    domain,
		domain:          domain,
		originApprovers: approvers,
		approvers:       approvers,
		originMessage:   message,
		message:         message,
	}

	var err error
	c.config, err = c.GetDomainConfig(context.Background())
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *CasbinHttpClient) customRequest(ctx context.Context, path string, request interface{}, reply interface{}) error {
	c.customSetEnforcerNameAndDomain(request)
	requestJson, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseUrl+path, bytes.NewBuffer(requestJson))
	if err != nil {
		return err
	}
	req = util.WrapperAuditInfo(req, c.approvers, c.message)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&reply)
	if err != nil {
		return err
	}

	return nil
}

// 使用反射，假定request中必然有EnforcerName和Domain字段
func (c *CasbinHttpClient) customSetEnforcerNameAndDomain(request interface{}) interface{} {
	v := reflect.ValueOf(request).Elem()
	enforcerNameField := v.FieldByName("EnforcerName")
	domainField := v.FieldByName("Domain")
	enforcerNameField.SetString(c.name)
	domainField.SetString(c.domain)
	return request
}

func (c *CasbinHttpClient) AddDomainConfig(ctx context.Context, domainConfig *config.CasbinConfig) error {
	var pbDomainConfig *pb.DomainConfig = &pb.DomainConfig{}

	var domainConfigRequest *pb.DomainConfigRequest = &pb.DomainConfigRequest{
		EnforcerName: domainConfig.Name,
		Domain:       domainConfig.Domain,
		DomainConfig: pbDomainConfig,
	}

	pbDomainConfig.ObjectClsOfRoleClsMap = make(map[string]*pb.DomainConfig_PermissionsOfObjectCls)
	for roleCls, objectClsMap := range domainConfig.PermissionOfRoleClsDict {
		pbDomainConfig.ObjectClsOfRoleClsMap[roleCls] = &pb.DomainConfig_PermissionsOfObjectCls{
			PermissionsOfObjectClsMap: make(map[string]*pb.DomainConfig_PermissionList),
		}
		for objectCls, permissions := range objectClsMap {
			pbDomainConfig.ObjectClsOfRoleClsMap[roleCls].PermissionsOfObjectClsMap[objectCls] = &pb.DomainConfig_PermissionList{
				Permissions: permissions,
			}
		}
	}

	if domainConfig.GetRoleClsFromRole("/r/m/1") == "/r/m" {
		pbDomainConfig.GetRoleClsFromRoleFuncName = "default"
	}
	if domainConfig.GetRoleClsFromRole("/r/m/1") == "/r" {
		pbDomainConfig.GetRoleClsFromRoleFuncName = "second"
	}

	if domainConfig.GetObjectClsFromObject("/o/c/1") == "/o/c" {
		pbDomainConfig.GetObjectClsFromObjectFuncName = "default"
	}
	if domainConfig.GetObjectClsFromObject("/o/c/1") == "/o" {
		pbDomainConfig.GetObjectClsFromObjectFuncName = "second"
	}

	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_AddDomainConfig_FullMethodName, domainConfigRequest, reply)
	if err != nil {
		return err
	}

	return nil
}

func (c *CasbinHttpClient) GetDomainConfig(ctx context.Context) (*config.CasbinConfig, error) {
	var reply *pb.DomainConfigReply = &pb.DomainConfigReply{}
	err := c.customRequest(ctx, pb.Casbin_GetDomainConfig_FullMethodName, &pb.EmptyRequest{}, reply)
	if err != nil {
		return nil, err
	}

	permissionOfRoleClsDict := make(map[string]map[string][]string)
	for roleCls, objectClsMap := range reply.DomainConfig.ObjectClsOfRoleClsMap {
		for objectCls, permissions := range objectClsMap.PermissionsOfObjectClsMap {
			if _, ok := permissionOfRoleClsDict[roleCls]; !ok {
				permissionOfRoleClsDict[roleCls] = make(map[string][]string)
			}

			permissionOfRoleClsDict[roleCls][objectCls] = permissions.Permissions
		}
	}

	var getRoleClsFromRoleFunc func(role string) string
	switch reply.DomainConfig.GetRoleClsFromRoleFuncName {
	case "default":
		getRoleClsFromRoleFunc = util.DefaultClsGetter
	case "second":
		getRoleClsFromRoleFunc = util.SecondClsGetter
	default:
		return nil, errors.New("unsupported GetRoleClsFromRoleFuncName: " + reply.DomainConfig.GetRoleClsFromRoleFuncName)
	}

	var getObjectClsFromObjectFunc func(object string) string
	switch reply.DomainConfig.GetObjectClsFromObjectFuncName {
	case "default":
		getObjectClsFromObjectFunc = util.DefaultClsGetter
	case "second":
		getObjectClsFromObjectFunc = util.SecondClsGetter
	default:
		return nil, errors.New("unsupported GetObjectClsFromObjectFuncName: " + reply.DomainConfig.GetObjectClsFromObjectFuncName)
	}

	return &config.CasbinConfig{
		Name:                    reply.DomainConfig.EnforcerName,
		Domain:                  reply.DomainConfig.Domain,
		PermissionOfRoleClsDict: permissionOfRoleClsDict,
		GetRoleClsFromRole:      getRoleClsFromRoleFunc,
		GetObjectClsFromObject:  getObjectClsFromObjectFunc,
	}, nil
}

func (c *CasbinHttpClient) AddPermissionUnitV2(ctx context.Context, request *pb.PermissionUnitV2Request) (*pb.IntReply, error) {
	var reply *pb.IntReply = &pb.IntReply{}
	err := c.customRequest(ctx, pb.Casbin_AddPermissionUnitV2_FullMethodName, request, reply)
	if err != nil {
		return &pb.IntReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) AddPermissionUnitsV2(ctx context.Context, request *pb.PermissionUnitsV2Request) (*pb.IntReply, error) {
	var reply *pb.IntReply = &pb.IntReply{}
	err := c.customRequest(ctx, pb.Casbin_AddPermissionUnitV2_FullMethodName, request, reply)
	if err != nil {
		return &pb.IntReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) RemovePermissionUnitV2(ctx context.Context, request *pb.PermissionUnitV2Request) (*pb.IntReply, error) {
	var reply *pb.IntReply = &pb.IntReply{}
	err := c.customRequest(ctx, pb.Casbin_RemovePermissionUnitV2_FullMethodName, request, reply)
	if err != nil {
		return &pb.IntReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) RemovePermissionUnitsV2(ctx context.Context, request *pb.PermissionUnitsV2Request) (*pb.IntReply, error) {
	var reply *pb.IntReply = &pb.IntReply{}
	err := c.customRequest(ctx, pb.Casbin_RemovePermissionUnitsV2_FullMethodName, request, reply)
	if err != nil {
		return &pb.IntReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) RemovePermissionUnitsV2AndGroupPoliciesForUserOrRole(ctx context.Context, request *pb.UserOrRoleRequest) (*pb.EmptyReply, error) {
	var reply *pb.EmptyReply = &pb.EmptyReply{}
	err := c.customRequest(ctx, pb.Casbin_RemovePermissionUnitsV2AndGroupPoliciesForUserOrRole_FullMethodName, request, reply)
	if err != nil {
		return &pb.EmptyReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) RemovePermissionUnitsV2AndGroupPoliciesForObject(ctx context.Context, request *pb.ObjectRequest) (*pb.EmptyReply, error) {
	var reply *pb.EmptyReply = &pb.EmptyReply{}
	err := c.customRequest(ctx, pb.Casbin_RemovePermissionUnitsV2AndGroupPoliciesForObject_FullMethodName, request, reply)
	if err != nil {
		return &pb.EmptyReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetPermissionInfoForUserOrRole(ctx context.Context, request *pb.UserOrRoleWithFlagRequest) (*pb.PermissionInfoReply, error) {
	var reply *pb.PermissionInfoReply = &pb.PermissionInfoReply{}
	err := c.customRequest(ctx, pb.Casbin_GetPermissionInfoForUserOrRole_FullMethodName, request, reply)
	if err != nil {
		return &pb.PermissionInfoReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetPermissionInfoForObject(ctx context.Context, request *pb.ObjectWithFlagRequest) (*pb.PermissionInfoReply, error) {
	var reply *pb.PermissionInfoReply = &pb.PermissionInfoReply{}
	err := c.customRequest(ctx, pb.Casbin_GetPermissionInfoForObject_FullMethodName, request, reply)
	if err != nil {
		return &pb.PermissionInfoReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetPermissionInfoForUserOrRoleAndObject(ctx context.Context, request *pb.UserOrRoleAndObjectRequest) (*pb.PermissionInfoReply, error) {
	var reply *pb.PermissionInfoReply = &pb.PermissionInfoReply{}
	err := c.customRequest(ctx, pb.Casbin_GetPermissionInfoForUserOrRoleAndObject_FullMethodName, request, reply)
	if err != nil {
		return &pb.PermissionInfoReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) ReplacePermissionInfoForUserOrRole(ctx context.Context, request *pb.ReplacePermissionInfoForUserOrRoleRequest) (*pb.PermissionInfoReply, error) {
	var reply *pb.PermissionInfoReply = &pb.PermissionInfoReply{}
	err := c.customRequest(ctx, pb.Casbin_ReplacePermissionInfoForUserOrRole_FullMethodName, request, reply)
	if err != nil {
		return &pb.PermissionInfoReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetObjectsForUserWithPermission(ctx context.Context, request *pb.AclSearchRequest) (*pb.ArrayReply, error) {
	var reply *pb.ArrayReply = &pb.ArrayReply{}
	err := c.customRequest(ctx, pb.Casbin_GetObjectsForUserWithPermission_FullMethodName, request, reply)
	if err != nil {
		return &pb.ArrayReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetObjectsForUserWithPermissionsEx(ctx context.Context, request *pb.AclSearchExRequest) (*pb.ArrayReply, error) {
	var reply *pb.ArrayReply = &pb.ArrayReply{}
	err := c.customRequest(ctx, pb.Casbin_GetObjectsForUserWithPermissionsEx_FullMethodName, request, reply)
	if err != nil {
		return &pb.ArrayReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetObjectTreesForUserWithPermissions(ctx context.Context, request *pb.AclSearchForObjectTreesRequest) (*pb.GroupPoliciesReply, error) {
	var reply *pb.GroupPoliciesReply = &pb.GroupPoliciesReply{}
	err := c.customRequest(ctx, pb.Casbin_GetObjectTreesForUserWithPermissions_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetPermissionsForUserWithObject(ctx context.Context, request *pb.AclSearchRequest) (*pb.ArrayReply, error) {
	var reply *pb.ArrayReply = &pb.ArrayReply{}
	err := c.customRequest(ctx, pb.Casbin_GetPermissionsForUserWithObject_FullMethodName, request, reply)
	if err != nil {
		return &pb.ArrayReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetPermissionsForUserWithObjectsEx(ctx context.Context, request *pb.AclSearchExRequest) (*pb.PermissionsWithObjectListReply, error) {
	var reply *pb.PermissionsWithObjectListReply = &pb.PermissionsWithObjectListReply{}
	err := c.customRequest(ctx, pb.Casbin_GetPermissionsForUserWithObjectsEx_FullMethodName, request, reply)
	if err != nil {
		return &pb.PermissionsWithObjectListReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetUsersOrRolesForObjectWithPermission(ctx context.Context, request *pb.AclSearchRequest) (*pb.ArrayReply, error) {
	var reply *pb.ArrayReply = &pb.ArrayReply{}
	err := c.customRequest(ctx, pb.Casbin_GetUsersOrRolesForObjectWithPermission_FullMethodName, request, reply)
	if err != nil {
		return &pb.ArrayReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) CheckPermission(ctx context.Context, request *pb.AclSearchRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_CheckPermission_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) BatchCheckPermission(ctx context.Context, request *pb.BatchAclSearchRequest) (*pb.BoolArrayReply, error) {
	var reply *pb.BoolArrayReply = &pb.BoolArrayReply{}
	err := c.customRequest(ctx, pb.Casbin_BatchCheckPermission_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolArrayReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) AddUserOrRoleForUserOrRole(ctx context.Context, request *pb.GroupPolicyRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_AddUserOrRoleForUserOrRole_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) AddUsersOrRolesForUsersOrRoles(ctx context.Context, request *pb.GroupPoliciesRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_AddUsersOrRolesForUsersOrRoles_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) RemoveUserOrRoleForUserOrRole(ctx context.Context, request *pb.GroupPolicyRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_RemoveUserOrRoleForUserOrRole_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) RemoveUsersOrRolesForUsersOrRoles(ctx context.Context, request *pb.GroupPoliciesRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_RemoveUsersOrRolesForUsersOrRoles_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetUsersOrRolesForUserOrRole(ctx context.Context, request *pb.UserOrRoleRequest) (*pb.GroupPoliciesReply, error) {
	var reply *pb.GroupPoliciesReply = &pb.GroupPoliciesReply{}
	err := c.customRequest(ctx, pb.Casbin_GetUsersOrRolesForUserOrRole_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetUsersOrRolesForUsersOrRoles(ctx context.Context, request *pb.UsersOrRolesRequest) (*pb.GroupPoliciesWithRootListReply, error) {
	var reply *pb.GroupPoliciesWithRootListReply = &pb.GroupPoliciesWithRootListReply{}
	err := c.customRequest(ctx, pb.Casbin_GetUsersOrRolesForUsersOrRoles_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesWithRootListReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetUsersOrRolesInUserOrRole(ctx context.Context, request *pb.UserOrRoleRequest) (*pb.GroupPoliciesReply, error) {
	var reply *pb.GroupPoliciesReply = &pb.GroupPoliciesReply{}
	err := c.customRequest(ctx, pb.Casbin_GetUsersOrRolesInUserOrRole_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetUsersOrRolesInUsersOrRoles(ctx context.Context, request *pb.UsersOrRolesRequest) (*pb.GroupPoliciesWithRootListReply, error) {
	var reply *pb.GroupPoliciesWithRootListReply = &pb.GroupPoliciesWithRootListReply{}
	err := c.customRequest(ctx, pb.Casbin_GetUsersOrRolesInUsersOrRoles_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesWithRootListReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetUsersOrRolesForUserOrRoleWithPattern(ctx context.Context, request *pb.UserOrRoleWithPatternRequest) (*pb.GroupPoliciesReply, error) {
	var reply *pb.GroupPoliciesReply = &pb.GroupPoliciesReply{}
	err := c.customRequest(ctx, pb.Casbin_GetUsersOrRolesForUserOrRoleWithPattern_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetUsersOrRolesInUserOrRoleWithPattern(ctx context.Context, request *pb.UserOrRoleWithPatternRequest) (*pb.GroupPoliciesReply, error) {
	var reply *pb.GroupPoliciesReply = &pb.GroupPoliciesReply{}
	err := c.customRequest(ctx, pb.Casbin_GetUsersOrRolesInUserOrRoleWithPattern_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) AddObjectForObject(ctx context.Context, request *pb.GroupPolicyRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_AddObjectForObject_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) AddObjectsForObjects(ctx context.Context, request *pb.GroupPoliciesRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_AddObjectsForObjects_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) RemoveObjectForObject(ctx context.Context, request *pb.GroupPolicyRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_RemoveObjectForObject_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) RemoveObjectsForObjects(ctx context.Context, request *pb.GroupPoliciesRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_RemoveObjectsForObjects_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetObjectsForObject(ctx context.Context, request *pb.ObjectRequest) (*pb.GroupPoliciesReply, error) {
	var reply *pb.GroupPoliciesReply = &pb.GroupPoliciesReply{}
	err := c.customRequest(ctx, pb.Casbin_GetObjectsForObject_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetObjectsForObjects(ctx context.Context, request *pb.ObjectsRequest) (*pb.GroupPoliciesWithRootListReply, error) {
	var reply *pb.GroupPoliciesWithRootListReply = &pb.GroupPoliciesWithRootListReply{}
	err := c.customRequest(ctx, pb.Casbin_GetObjectsForObjects_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesWithRootListReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetObjectsInObject(ctx context.Context, request *pb.ObjectRequest) (*pb.GroupPoliciesReply, error) {
	var reply *pb.GroupPoliciesReply = &pb.GroupPoliciesReply{}
	err := c.customRequest(ctx, pb.Casbin_GetObjectsInObject_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetObjectsInObjects(ctx context.Context, request *pb.ObjectsRequest) (*pb.GroupPoliciesWithRootListReply, error) {
	var reply *pb.GroupPoliciesWithRootListReply = &pb.GroupPoliciesWithRootListReply{}
	err := c.customRequest(ctx, pb.Casbin_GetObjectsInObjects_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesWithRootListReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetObjectsForObjectWithPattern(ctx context.Context, request *pb.ObjectWithPatternRequest) (*pb.GroupPoliciesReply, error) {
	var reply *pb.GroupPoliciesReply = &pb.GroupPoliciesReply{}
	err := c.customRequest(ctx, pb.Casbin_GetObjectsForObjectWithPattern_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) GetObjectsInObjectWithPattern(ctx context.Context, request *pb.ObjectWithPatternRequest) (*pb.GroupPoliciesReply, error) {
	var reply *pb.GroupPoliciesReply = &pb.GroupPoliciesReply{}
	err := c.customRequest(ctx, pb.Casbin_GetObjectsInObjectWithPattern_FullMethodName, request, reply)
	if err != nil {
		return &pb.GroupPoliciesReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) AddRolePermissionUnit(ctx context.Context, request *pb.RolePermissionUnitRequest) (*pb.RolePermissionUnitReply, error) {
	var reply *pb.RolePermissionUnitReply = &pb.RolePermissionUnitReply{}
	err := c.customRequest(ctx, pb.Casbin_AddRolePermissionUnit_FullMethodName, request, reply)
	if err != nil {
		return &pb.RolePermissionUnitReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) RemoveRolePermissionUnit(ctx context.Context, request *pb.UserOrRoleRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_RemoveRolePermissionUnit_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) RemoveRolePermissionUnits(ctx context.Context, request *pb.UserOrRoleRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_RemoveRolePermissionUnits_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}

func (c *CasbinHttpClient) IsMaster(ctx context.Context, request *pb.EmptyRequest) (*pb.BoolReply, error) {
	var reply *pb.BoolReply = &pb.BoolReply{}
	err := c.customRequest(ctx, pb.Casbin_IsMaster_FullMethodName, request, reply)
	if err != nil {
		return &pb.BoolReply{}, err
	}

	return reply, nil
}
