package httpclient

import pb "github.com/1000happiness/casbin-client-go/proto"

func (c *CasbinHttpClient) BuildPermissionUnitV2(user string, roleCls string, object string) *pb.PermissionUnitV2 {
	return &pb.PermissionUnitV2{
		User:        user,
		RoleCls:     roleCls,
		Object:      object,
		Permissions: c.config.PermissionOfRoleClsDict[c.config.GetRoleClsFromRole(roleCls)][c.config.GetObjectClsFromObject(object)],
	}
}
