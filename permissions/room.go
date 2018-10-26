package permissions

import (
	"fmt"
	"strings"
	"time"

	"github.com/byuoitav/common/nerr"
	"github.com/byuoitav/endpoint-authorization-controller/base"
	"github.com/byuoitav/endpoint-authorization-controller/db"
	"github.com/byuoitav/endpoint-authorization-controller/users"
)

//CalculateRoomPermissions given the request with the 'room' resource type - calculate the permissions allowed.
//We assume that the Access Key associated with the request has already been validated.
func CalculateRoomPermissions(req base.UserInformation) (base.Response, *nerr.E) {
	toReturn := base.Response{
		UserInformation: req,
	}

	//set of roles
	roles := map[string]bool{}

	if req.ResourceType != base.Room {
		return toReturn, nerr.Create(fmt.Sprintf("Invalid request type. Must be %v", base.Room), "invalid-type")
	}

	//we need to get the list of groups for the user
	groups, err := users.GetGroupsForUser(req.ID)
	if err != nil {
		return toReturn, err.Addf("Couldn't calcualte room permissions for %v", req.ResourceID)
	}

	//we need to get the list of permissions associated with the type and id
	records, err := db.GetPermissionRecords(req.ResourceType, req.ResourceID)
	if err != nil {
		return toReturn, err.Addf("Couldn't calcualte room permissions for %v", req.ResourceID)
	}

	//check all the levels of the requested id:
	vals := strings.Split(req.ResourceID, "-")

	curTTL := 0
	//start at the 'all' level and look at the permissions denoted there
	if v, ok := records["*"]; ok {

		for k, j := range v.Allow {
			if _, ok := groups[k]; ok {

				//set the TTL
				if j.TTL != nil {
					if curTTL == 0 || curTTL > *j.TTL {
						curTTL = *j.TTL
					}
				}

				//everything is allow at this point
				for _, l := range j.Roles {
					roles[l] = true
				}
			}
		}
	}

	cur := ""
	for _, i := range vals {
		cur = cur + i
		if v, ok := records[cur]; ok {
			//do our Deny first, since we can reverse this later with the allows
			for k, j := range v.Deny {
				if _, ok := groups[k]; ok {

					//set the TTL
					if j.TTL != nil {
						if curTTL == 0 || curTTL > *j.TTL {
							curTTL = *j.TTL
						}
					}

					for _, l := range j.Roles {
						roles[l] = false
					}
				}
			}
			//allow permissions override
			for k, j := range v.Allow {
				if _, ok := groups[k]; ok {

					//set the TTL
					if j.TTL != nil {
						if curTTL == 0 || curTTL > *j.TTL {
							curTTL = *j.TTL
						}
					}

					for _, l := range j.Roles {
						roles[l] = true
					}
				}
			}
		}
		cur = cur + "-"
	}

	toReturn.TTL = time.Now().Add(time.Duration(curTTL) * time.Second)

	//we need to check if resource being requested was a leaf node or not.
	v, ok := records[req.ResourceID]
	if !ok || v.Leaf { //it was a leaf.
		for k, v := range roles {
			if v {
				toReturn.Permissions[req.ResourceID] = append(toReturn.Permissions[req.ResourceID], k)
			}
		}
	} else {
		//we need to now go through the rest of the items in the records returned and calculate the permissions for each leaf node - we can do this by checking the 'SubResources' field of the requested ID

	}

	return toReturn, nil
}
