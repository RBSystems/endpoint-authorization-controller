package couch

import "github.com/byuoitav/endpoint-authorization-controller/base"

type bulkDocRetrievalResponse struct {
	Rows []struct {
		ID  string                 `json:"id"`
		Key string                 `json:"key"`
		Doc base.PermissionsRecord `json:"doc"`
	} `json:"rows"`
}

type bulkKeyRetrievalResponse struct {
	Rows []struct {
		ID  string         `json:"id"`
		Key string         `json:"key"`
		Doc base.KeyRecord `json:"doc"`
	} `json:"rows"`
}

type bulkDocRetrievalRequest struct {
	Keys  []string `json:"keys,omitempty"`
	Limit int      `json:"limit,omitempty"`
}

func getDocument(resp bulkDocRetrievalResponse, id string) (bool, base.PermissionsRecord) {
	for i := range resp.Rows {
		if resp.Rows[i].Doc.ID == id {
			return true, resp.Rows[i].Doc
		}
	}
	return false, base.PermissionsRecord{}
}
