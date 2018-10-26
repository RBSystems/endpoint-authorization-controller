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

//GetPermissionRecords .
func (a *AuthDB) GetPermissionRecords(reqType, reqID string) (map[string]base.PermissionsRecord, *nerr.E) {
	return map[string]base.PermissionsRecord{}, nil
}
