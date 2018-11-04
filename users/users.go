package users

import (
	"github.com/byuoitav/common/nerr"
	"github.com/byuoitav/endpoint-authorization-controller/users/activedirectory"
)

//usertypes
const (
	LDAP = "ldap"
)

//GetGroupsForUser .
func GetGroupsForUser(id string, usertype string) ([]string, *nerr.E) {
	switch usertype {
	case LDAP:
		return activedirectory.GetGroupsForUser(id)
	}

	return []string{}, nerr.Create("Unknown usertype type: %v", usertype)
}
