package domain

import "github.com/hailooss/service/config"

func ReadRolesForGroups(groups []string) []string {
	roles := []string{}

	for _, group := range groups {
		groupRoles := config.AtPath("hailo", "service", "authentication", "groups", group).AsStringArray()

		roles = append(roles, groupRoles...)
	}

	return roles
}
