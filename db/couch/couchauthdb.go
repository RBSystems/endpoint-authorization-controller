package couch

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/byuoitav/common/db"
	c "github.com/byuoitav/common/db/couch"
	"github.com/byuoitav/common/log"
	"github.com/byuoitav/common/nerr"
	"github.com/byuoitav/endpoint-authorization-controller/base"
)

//database type const
const (
	COUCH = "couch"
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
//If the leaf resource does not exist in the resource list, the request will go through with a blank record created.
func (a *AuthDB) GetPermissionRecords(reqType, reqID string) (map[string]base.PermissionsRecord, *nerr.E) {
	toReturn := map[string]base.PermissionsRecord{}

	d, ok := db.GetDB().(*c.CouchDB)
	if !ok {
		return toReturn, nerr.Create("No couch database configured", "bad-config")
	}

	//check to see if I'm requesting all docs
	if reqID == "*" {
		//get everything

	} else {
		req := bulkDocRetrievalRequest{}

		//add the start doc
		req.Keys = append(req.Keys, "*")

		parts := strings.Split(reqID, "-")
		cur := ""
		for i := range parts {
			cur = cur + parts[i]
			req.Keys = append(req.Keys, cur)
			cur = cur + "-"
		}

		req.Limit = len(req.Keys)

		b, err := json.Marshal(req)
		if err != nil {
			return toReturn, nerr.Translate(err).Addf("Couldn't get permissions records. Couldn't marshal request")
		}

		resp := bulkDocRetrievalResponse{}
		//now we make the request
		endpoint := fmt.Sprintf("%v/_all_docs?include_docs=true", reqType)
		err = d.MakeRequest("GET", endpoint, "application/json", b, &resp)
		if err != nil {
			log.L.Warnf("Couldn't get permission record: %v", err.Error())
			return toReturn, nerr.Translate(err).Addf("Couln't get permission records")
		}

		//find the star doc
		var found bool
		found, toReturn["*"] = getDocument(resp, "*")
		if !found {
			return toReturn, nerr.Create(fmt.Sprintf("No base level permission defined for type: %v", reqType), "invalidConfiguration")
		}
		log.L.Debugf("Processed roles for the * record.")

		//we check to see if we're asking for a leaf resource or a parent resource
		if len(parts) > toReturn["*"].ResourceTiers {
			return toReturn, nerr.Create(fmt.Sprintf("requested invalid resource %v for type %v", reqID, reqType), "invalid-request")
		}
		log.L.Debugf("Getting resource permissions until %v", reqID)

		//Check to make sure we have one for each of our sets, if not we need to create one for the intermediaries and fill the subresources field.
		cur = parts[0]
		starrec := toReturn["*"]
		starrec.SubResources = []string{cur}
		toReturn["*"] = starrec

		log.L.Debugf("Adding subresources %v to the starrec", toReturn["*"].SubResources)
		//we need to add the subrecord from the star record

		for i := 0; i < len(parts); i++ {
			var next string
			if i != len(parts)-1 {
				next = cur + "-" + parts[i]
			}

			_, currec := getDocument(resp, cur)
			if len(next) > 0 {
				currec.SubResources = append(currec.SubResources, next)
			}
			log.L.Debugf("adding record for %v", cur)

			toReturn[cur] = currec
			cur = next
		}

		//we can abort if we're at a leaf resource
		if len(parts) == toReturn["*"].ResourceTiers {
			log.L.Debugf("At a leaf node, returning.")
			return toReturn, nil
		}

		log.L.Debugf("Getting resource list.")
		//we're getting a set of resources, so things get more complex
		rlist := toReturn["*"].ResourceList

		//assume that we have a starting point, so now we need to go get all of the child resources from the resource database, as well as all children resources from the permissions database
		var list []string
		switch rlist.Type {
		case COUCH:
			var err *nerr.E
			list, err = GetResourceList(rlist, reqID)
			if err != nil {
				return toReturn, err.Addf("Couldn't generate resources list.")
			}
		}

		retReq := bulkDocRetrievalRequest{
			Keys: list,
		}

		for i := range list {
			tmp := strings.TrimPrefix(list[i], reqID)
			if strings.Contains(tmp, "-") {
				cur := ""
				//we need to go through and add a request for it's parent document.
				s := strings.Split(tmp, "-")
				for j := 0; j < len(s)-1; j++ {
					if s[j] == "" {
						continue
					}

					cur = cur + s[j]
					retReq.Keys = append(retReq.Keys, cur)
				}
			}
		}

		resp = bulkDocRetrievalResponse{}

		b, err = json.Marshal(retReq)
		if err != nil {
			return toReturn, nerr.Translate(err).Addf("Failed to get permissions documents. Coudn't marshal request for permsission docuements.")
		}

		//now we have the list we need to get all of their resources, and any intermediary resources as well
		err = d.MakeRequest("POST", endpoint, "application/json", b, &resp)
		if err != nil {
			log.L.Warnf("Couldn't get permission record: %v", err.Error())
			return toReturn, nerr.Translate(err).Addf("Couln't get permission records")
		}
		log.L.Debugf("resp: %+v", resp)

		subr := map[string][]string{}

		//go through all the resources we requested, and we need to see if a) they exist, and b) if they have subresources
		for i := range retReq.Keys {
			if _, ok := subr[retReq.Keys[i]]; !ok {
				subr[retReq.Keys[i]] = []string{}
			}

			tmp := strings.TrimPrefix(retReq.Keys[i], reqID+"-")
			if indx := strings.LastIndex(tmp, "-"); indx != -1 {
				//we need to add this to the subdocs for it's parent.
				//remove the last dash
				parent := reqID + "-" + tmp[:indx]
				subr[parent] = append(subr[parent], retReq.Keys[i])
			} else {
				subr[reqID] = append(subr[reqID], retReq.Keys[i])
			}
		}

		//there's an entry in subr for every entry
		for k, v := range subr {
			if found, t := getDocument(resp, k); found {
				log.L.Debugf("Adding record from DB for: %v", t)
				t.SubResources = v
				toReturn[k] = t
				continue
			} else {
				if record, ok := toReturn[k]; ok {
					log.L.Debugf("Adding subresources for %v", k)
					record.SubResources = v
					toReturn[k] = record
				} else {
					log.L.Debugf("Building resource record for %v", k)
					toReturn[k] = base.PermissionsRecord{
						ID:           k,
						ResourceType: reqType,
						SubResources: v,
					}
				}
			}
		}
	}

	return toReturn, nil
}
