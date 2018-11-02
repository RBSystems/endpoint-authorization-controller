package couch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/byuoitav/common/db/couch"
	"github.com/byuoitav/common/log"
	"github.com/byuoitav/common/nerr"
	"github.com/byuoitav/endpoint-authorization-controller/base"
)

//GetResourceList .
func GetResourceList(rlist base.ResourceList, id string) ([]string, *nerr.E) {
	log.L.Debugf("Getting resource list for subresources of %v", id)
	toReturn := []string{}
	//we assume that the resource list is the IDs of records in the couch database denoted by addr, and that the id (if not *) corresponds to a 'full' parent resource.

	resp, err := getAllResources(rlist)
	if err != nil {
		return toReturn, err.Addf("Couldn't parse resource list")
	}
	log.L.Debugf("Found %v total resources from %v", len(resp.Rows), rlist.Address)
	for i := range resp.Rows {
		if strings.HasPrefix(resp.Rows[i].ID, id) {
			toReturn = append(toReturn, resp.Rows[i].ID)
		}
	}
	log.L.Debugf("Found %v subresources of %v.", len(toReturn), id)

	return toReturn, nil
}

func getAllResources(rlist base.ResourceList) (bulkDocRetrievalResponse, *nerr.E) {
	toReturn := bulkDocRetrievalResponse{}

	//we assume that the resource list is the IDs of records in the couch database denoted by addr, and that the id (if not *) corresponds to a 'full' parent resource.

	body := bulkDocRetrievalRequest{}
	body.Limit = 100000

	b, err := json.Marshal(&body)
	if err != nil {
		return toReturn, nerr.Translate(err).Addf("Couldn't get resource list")
	}
	log.L.Debugf("Getting all resources from %v", rlist.Address)

	req, err := http.NewRequest("POST", rlist.Address+"/_all_docs", bytes.NewReader(b))
	if err != nil {
		return toReturn, nerr.Translate(err).Addf("Couldn't get resource list")
	}
	req.Header.Add("accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	//basic auth
	pass, user := getCreds(rlist)
	req.SetBasicAuth(user, pass)

	resp, err := client.Do(req)
	if err != nil {
		return toReturn, nerr.Translate(err).Addf("Couldn't get resource list")
	}

	defer resp.Body.Close()

	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return toReturn, nerr.Translate(err).Addf("Couldn't Get resource list")
	}

	if resp.StatusCode/100 != 2 {
		var ce couch.CouchError
		err = json.Unmarshal(b, &ce)
		if err != nil {
			return toReturn, nerr.Create(fmt.Sprintf("received a non-200 response from %v. Body: %s", rlist.Address, b), "bad-response")
		}

		log.L.Infof("Non-200 response: %v", ce.Error)
		return toReturn, nerr.Translate(couch.CheckCouchErrors(ce)).Addf("Couldn't get resource list")
	}

	err = json.Unmarshal(b, &toReturn)
	if err != nil {
		return toReturn, nerr.Translate(err).Addf("Couldn't get resource list. Invalid responce from database")
	}

	//we have a list of all of the rooms - now we need to process
	return toReturn, nil
}

func getCreds(rlist base.ResourceList) (pass string, user string) {
	//do the password
	if strings.HasPrefix(rlist.Pass, "ENV") {
		s := strings.TrimPrefix(rlist.Pass, "ENV ")
		pass = os.Getenv(s)
	} else {
		pass = rlist.Pass
	}

	//do the username
	if strings.HasPrefix(rlist.User, "ENV") {
		s := strings.TrimPrefix(rlist.User, "ENV ")
		user = os.Getenv(s)
	} else {
		user = rlist.User
	}

	return
}
