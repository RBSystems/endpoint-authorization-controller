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

// Authentication method constants
const (
	WSO2            = "wso2"
	CAS             = "cas"
	Application     = "APPLICATION"
	ApplicationUser = "APPLICATION_USER"
)

//GetAuthorization .
// func GetAuthorization(req base.Request) (base.Response, *nerr.E) {
// 	toReturn := base.Response{
// 		CommonInfo: req.UserInformation.CommonInfo,
// 	}

// 	//check the API key
// 	keyrec, err := db.GetAuthDB(couch.COUCH).GetKeyRecord(req.AccessKey)
// 	if err != nil {
// 		return toReturn, err.Addf("Couldn't authorize api key")
// 	}

// 	if !keyrec.Valid {
// 		return toReturn, nerr.Create(fmt.Sprintf("API key is invalid"), "invalid-key")
// 	}

// 	log.L.Infof("userID: %v", req.UserInformation.ID)
// 	var groups []string
// 	if req.UserInformation.ID == base.SERVICEUSER {
// 		if keyrec.Service {
// 			//we get the permissions based on the gruops defined on the service
// 			groups = keyrec.Groups
// 		} else {
// 			return toReturn, nerr.Create(fmt.Sprintf("API Key not valid for service user."), "bad-user")
// 		}
// 	} else {
// 		//we need to get the groups for the user from AD
// 		groups, err = users.GetGroupsForUser(req.UserInformation.ID, users.LDAP)
// 		if err != nil {
// 			return toReturn, err.Addf("couldn't generate authorizations")
// 		}
// 	}

// 	//add permission types here
// 	switch req.UserInformation.ResourceType {
// 	case base.Room:
// 		toReturn, err := room.CalculateRoomPermissions(req.UserInformation, groups)
// 		if err != nil {
// 			return toReturn, err.Addf("Couldn't generate authorizations")
// 		}
// 		return toReturn, nil
// 	}
// 	log.L.Debugf("%v", toReturn.ID)

// 	return toReturn, nil
// }

//GetAuthorization .
func GetAuthorization(req base.Request) (base.Response, *nerr.E) {
	var groups *[]string

	switch req.UserInformation.AuthMethod {
	case WSO2:
		ok, ne := getWSO2Authorization(req, *groups)
		if ne != nil {
			log.L.Errorf("something went wrong : %s", ne.String())
			return base.Response{}, nil
		}
		if !ok {
			log.L.Errorf("user not authorized")
			return base.Response{}, nil
		}
	case CAS:
		ok, ne := getCASAuthorization(req, *groups)
		if ne != nil {
			log.L.Errorf("something went wrong : %s", ne.String())
			return base.Response{}, nil
		}
		if !ok {
			log.L.Errorf("user not authorized")
			return base.Response{}, nil
		}
	default:
		return base.Response{}, nil
	}

	toReturn := base.Response{
		CommonInfo: req.UserInformation.CommonInfo,
	}

	switch req.UserInformation.ResourceType {
	case base.Room:
		toReturn, err := room.CalculateRoomPermissions(req.UserInformation, *groups)
		if err != nil {
			return toReturn, err.Addf("Couldn't generate authorizations")
		}
		return toReturn, nil
	}
	log.L.Debugf("%v", toReturn.ID)

	return toReturn, nil
}

func getCASAuthorization(req base.Request, groups []string) (bool, *nerr.E) {
	//check the API key
	keyrec, err := db.GetAuthDB(couch.COUCH).GetKeyRecord(req.AccessKey)
	if err != nil {
		return false, err.Addf("Couldn't authorize api key")
	}

	if !keyrec.Valid {
		return false, nerr.Create(fmt.Sprintf("API key is invalid"), "invalid-key")
	}

	log.L.Infof("userID: %v", req.UserInformation.ID)
	if req.UserInformation.ID == base.SERVICEUSER {
		if keyrec.Service {
			//we get the permissions based on the gruops defined on the service
			groups = keyrec.Groups
		} else {
			return false, nerr.Create(fmt.Sprintf("API Key not valid for service user."), "bad-user")
		}
	} else {
		//we need to get the groups for the user from AD
		groups, err = users.GetGroupsForUser(req.UserInformation.ID, users.LDAP)
		if err != nil {
			return false, err.Addf("couldn't generate authorizations")
		}
	}

	return true, nil
}

func getWSO2Authorization(req base.Request, groups []string) (bool, *nerr.E) {
	// check if the token is valid
	ok, token, err := Validate(string(req.UserInformation.Data))
	if err != nil {
		return false, nerr.Translate(err).Addf("JWT token is invalid")
	}

	if !ok {
		return false, nil
	}

	// get the username out of the JWT
	req.AccessKey = token.Header["client_byu_id"].(string)

	//check the API key
	keyrec, ne := db.GetAuthDB(couch.COUCH).GetKeyRecord(req.AccessKey)
	if err != nil {
		return false, ne.Addf("Couldn't authorize api key")
	}

	if !keyrec.Valid {
		return false, nerr.Create(fmt.Sprintf("API key is invalid"), "invalid-key")
	}

	// get the usertype
	usertype := token.Header["http://wso2.org/claims/usertype"].(string)

	if usertype == Application {
		if keyrec.Service {
			//we get the permissions based on the gruops defined on the service
			groups = keyrec.Groups
		} else {
			return false, nerr.Create(fmt.Sprintf("API Key not valid for service user."), "bad-user")
		}
	} else if usertype == ApplicationUser {
		req.UserInformation.ID = token.Header["http://byu.edu/claims/resourceowner_net_id"].(string)

		groups, ne = users.GetGroupsForUser(req.UserInformation.ID, users.LDAP)
		if ne != nil {
			return false, ne.Addf("Couldn't generate authorizations")
		}

	}

	return true, nil
}
