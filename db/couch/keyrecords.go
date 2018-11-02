package couch

import (
	"encoding/json"
	"fmt"

	"github.com/byuoitav/common/db"
	c "github.com/byuoitav/common/db/couch"
	"github.com/byuoitav/common/log"
	"github.com/byuoitav/common/nerr"
	"github.com/byuoitav/endpoint-authorization-controller/base"
)

//GetKeyRecord .
func GetKeyRecord(key string) (base.KeyRecord, *nerr.E) {
	toReturn := base.KeyRecord{}

	d, ok := db.GetDB().(*c.CouchDB)
	if !ok {
		return toReturn, nerr.Create("No couch database configured", "bad-config")
	}

	resp := bulkKeyRetrievalResponse{}

	req := bulkDocRetrievalRequest{
		Limit: 1000,
	}
	b, err := json.Marshal(req)
	if err != nil {
		return toReturn, nerr.Translate(err).Addf("Couldn't get permissions records. Couldn't marshal request")
	}

	endpoint := fmt.Sprintf("api-keys/_all_docs?include_docs=true")
	err = d.MakeRequest("GET", endpoint, "application/json", b, &resp)
	if err != nil {
		log.L.Warnf("Couldn't get permission record: %v", err.Error())
		return toReturn, nerr.Translate(err).Addf("Couln't get permission records")
	}

	for i := range resp.Rows {
		if resp.Rows[i].Doc.Key == key {
			return resp.Rows[i].Doc, nil
		}
	}
	return toReturn, nerr.Create(key+" is an invalid key.", "Invalid key")
}
