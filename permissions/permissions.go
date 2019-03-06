package permissions

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"

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
	var groups []string
	var ok bool
	var ne *nerr.E
	log.L.Infof("getting permissions for %s with %s", req.UserInformation.ID, req.UserInformation.ResourceID)

	switch req.UserInformation.AuthMethod {
	case WSO2:
		ok, groups, ne = getWSO2Authorization(req)
		if ne != nil {
			log.L.Errorf("something went wrong : %s", ne.String())
			return base.Response{}, nil
		}
		if !ok {
			log.L.Errorf("user not authorized")
			return base.Response{}, nil
		}
	case CAS:
		ok, groups, ne = getCASAuthorization(req)
		log.L.Debugf("Groups 2: %s - Should be the same", groups)
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

	toReturn, err := room.CalculateResourcePermissions(req.UserInformation, groups)
	if err != nil {
		return toReturn, err.Addf("Couldn't generate authorizations")
	}
	log.L.Debugf("toReturn: %v", toReturn)
	return toReturn, nil

}

func getCASAuthorization(req base.Request) (bool, []string, *nerr.E) {
	//check the API key
	var groups []string
	log.L.Debug("Getting Key record for CAS")
	keyrec, err := db.GetAuthDB(couch.COUCH).GetKeyRecord(req.AccessKey)
	if err != nil {
		return false, groups, err.Addf("Couldn't authorize api key")
	}

	if !keyrec.Valid {
		return false, groups, nerr.Create(fmt.Sprintf("API key is invalid"), "invalid-key")
	}

	log.L.Infof("userID: %v", req.UserInformation.ID)
	if req.UserInformation.ID == base.SERVICEUSER {
		if keyrec.Service {
			//we get the permissions based on the gruops defined on the service
			groups = keyrec.Groups
		} else {
			return false, groups, nerr.Create(fmt.Sprintf("API Key not valid for service user."), "bad-user")
		}
	} else {
		//we need to get the groups for the user from AD
		groups, err = users.GetGroupsForUser(req.UserInformation.ID, users.LDAP)
		if err != nil {
			return false, groups, err.Addf("couldn't generate authorizations")
		}
	}
	log.L.Debugf("Groups: %s", groups)
	return true, groups, nil
}

func getWSO2Authorization(req base.Request) (bool, []string, *nerr.E) {
	// check if the token is valid
	var groups []string

	ok, token, err := Validate(string(req.UserInformation.Data))
	if err != nil {
		return false, groups, nerr.Translate(err).Addf("JWT token is invalid")
	}

	if !ok {
		return false, groups, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.L.Error("failed to case to MapClaims")
	}

	log.L.Debug(claims)
	// get the username out of the JWT
	req.AccessKey = claims["http://byu.edu/claims/client_byu_id"].(string)

	//check the API key
	keyrec, ne := db.GetAuthDB(couch.COUCH).GetKeyRecord(req.AccessKey)
	if err != nil {
		return false, groups, ne.Addf("Couldn't authorize api key")
	}

	if !keyrec.Valid || !keyrec.HasAuthMethod(req.UserInformation.AuthMethod) {
		return false, groups, nerr.Create(fmt.Sprintf("API key is invalid"), "invalid-key")
	}

	// get the usertype
	usertype := claims["http://wso2.org/claims/usertype"].(string)

	if usertype == Application {
		if keyrec.Service {
			//we get the permissions based on the gruops defined on the service
			groups = keyrec.Groups
		} else {
			return false, groups, nerr.Create(fmt.Sprintf("API Key not valid for service user."), "bad-user")
		}
	} else if usertype == ApplicationUser {
		req.UserInformation.ID = claims["http://byu.edu/claims/resourceowner_net_id"].(string)

		groups, ne = users.GetGroupsForUser(req.UserInformation.ID, users.LDAP)
		if ne != nil {
			return false, groups, ne.Addf("Couldn't generate authorizations")
		}

	}

	return true, groups, nil
}
