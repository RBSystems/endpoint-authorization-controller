package db

import (
	"sync"

	"github.com/byuoitav/common/nerr"
	"github.com/byuoitav/endpoint-authorization-controller/base"
	"github.com/byuoitav/endpoint-authorization-controller/db/couch"
)

//AuthDB .
type AuthDB interface {
	GetPermissionRecords(reqType, reqID string) (map[string]base.PermissionsRecord, *nerr.E)
	GetKeyRecord(KeyID string) (base.KeyRecord, *nerr.E)
}

var authDBs map[string]AuthDB
var once sync.Once

//GetAuthDB .
func GetAuthDB(t string) AuthDB {
	once.Do(func() {
		authDBs = map[string]AuthDB{
			couch.COUCH: couch.GetDB(),
		}
	})

	return authDBs[t]
}

//GetPermissionRecords retrieves all the relevant permission structures for the ID requested.
//if reqID doesn't correspond to a 'leaf' resource, all sub-resources will be included.
//if reqID does correpond to a 'leaf' node, ALL non leaf resources will have a record included. If one is not defined in the database, one will be generated with blank permissions.
//The leaf record itself MAY be omitted if not explicitly defined in the permissions database - but it's reccommneded that it have a blank record generated as well.
func GetPermissionRecords(reqType, reqID string) (map[string]base.PermissionsRecord, *nerr.E) {

	return GetAuthDB("couch").GetPermissionRecords(reqType, reqID)
}

//GetKeyRecord .
func GetKeyRecord(Key string) (base.KeyRecord, *nerr.E) {
	return GetAuthDB("couch").GetKeyRecord(Key)
}
