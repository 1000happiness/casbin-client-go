package config

type CasbinConfig struct {
	Name                    string
	Domain                  string
	PermissionOfRoleClsDict map[string]map[string][]string
	GetRoleClsFromRole      func(role string) string
	GetObjectClsFromObject  func(object string) string
}
