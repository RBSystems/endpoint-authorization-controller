package permissions

import (
	"fmt"

	"github.com/byuoitav/common/log"
	"github.com/byuoitav/common/nerr"
	"github.com/byuoitav/endpoint-authorization-controller/base"
	"github.com/byuoitav/endpoint-authorization-controller/db"
	"github.com/byuoitav/endpoint-authorization-controller/db/couch"
	"github.com/byuoitav/endpoint-authorization-controller/permissions/room"
	"github.com/byuoitav/endpoint-authorization-controller/users"
)

//GetAuthorization .
func GetAuthorization(req base.Request) (base.Response, *nerr.E) {
	toReturn := base.Response{
		CommonInfo: req.UserInformation.CommonInfo,
	}

	//check the API key
	keyrec, err := db.GetAuthDB(couch.COUCH).GetKeyRecord(req.AccessKey)
	if err != nil {
		return toReturn, err.Addf("Couldn't authorize api key")
	}

	if !keyrec.Valid {
		return toReturn, nerr.Create(fmt.Sprintf("API key is invalid"), "invalid-key")
	}

	log.L.Infof("userID: %v", req.UserInformation.ID)
	var groups []string
	if req.UserInformation.ID == base.SERVICEUSER {
		if keyrec.Service {
			//we get the permissions based on the gruops defined on the service
			groups = keyrec.Groups
		} else {
			return toReturn, nerr.Create(fmt.Sprintf("API Key not valid for service user."), "bad-user")
		}
	} else {
		//we need to get the groups for the user from AD
		groups, err = users.GetGroupsForUser(req.UserInformation.ID, users.LDAP)
		if err != nil {
			return toReturn, err.Addf("couldn't generate authorizations")
		}
	}

	//add permission types here
	switch req.UserInformation.ResourceType {
	case base.Room:
		perms, err := room.CalculateRoomPermissions(req.UserInformation, groups)
		if err != nil {
			return toReturn, err.Addf("Couldn't generate authorizations")
		}
		return perms, nil
	}

	return toReturn, nil
}
