package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/byuoitav/common/log"
	"github.com/byuoitav/endpoint-authorization-controller/base"
	"github.com/byuoitav/endpoint-authorization-controller/permissions"
)

func TestVSlice(t *testing.T) {
	//log.SetLevel("warn")

	startTime := time.Now()
	req := base.UserInformation{
		ResourceID: "JFSB",
		CommonInfo: base.CommonInfo{
			ID:           "service",
			AuthMethod:   "CAS",
			ResourceType: "room",
		}}

	perms, err := permissions.GetAuthorization(base.Request{
		UserInformation: req,
		AccessKey:       "Ginger",
	})
	if err != nil {
		log.L.Errorf("%v", err.Error())
		log.L.Infof("%s", err.Stack)
	}
	log.L.Infof("%+v", perms)
	endtime := time.Now()
	fmt.Printf("Time elapsed: %v\n", endtime.Sub(startTime).String())
}
