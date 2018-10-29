package couch

import (
	"github.com/byuoitav/common/nerr"
	"github.com/byuoitav/endpoint-authorization-controller/base"
)

//AuthDB .
type AuthDB struct {
}

//GetDB .
func GetDB() *AuthDB {
	return &AuthDB{}
}

//GetPermissionRecords retrieves all the relevant permission structures for the ID requested.
//if reqID doesn't correspond to a 'leaf' resource, all sub-resources will be included.
//if reqID does correpond to a 'leaf' node, ALL non leaf resources will have a record included. If one is not defined in the database, one will be generated with blank permissions.
//The leaf record itself MAY be omitted if not explicitly defined in the permissions database - but it's reccommneded that it have a blank record generated as well.
func (a *AuthDB) GetPermissionRecords(reqType, reqID string) (map[string]base.PermissionsRecord, *nerr.E) {

	return map[string]base.PermissionsRecord{}, nil
}
