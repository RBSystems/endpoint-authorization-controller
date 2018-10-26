package db

import (
	"github.com/byuoitav/common/nerr"
	"github.com/byuoitav/endpoint-authorization-controller/base"
)

//GetPermissionRecords retrieves all the relevant permission structures for the ID requested
func GetPermissionRecords(reqType, reqID string) (map[string]base.PermissionsRecord, *nerr.E) {

	return map[string]base.PermissionsRecord{}, nil
}
