package main

import (
	"github.com/byuoitav/common/log"
	"github.com/byuoitav/endpoint-authorization-controller/base"
	"github.com/byuoitav/endpoint-authorization-controller/permissions/room"
)

func main() {
	//port := ":7200"
	//router := common.NewRouter()
	log.SetLevel("debug")

	req := base.UserInformation{
		ResourceID: "JFSB",
		CommonInfo: base.CommonInfo{
			ID:           "service",
			AuthMethod:   "CAS",
			ResourceType: "room",
		}}

	perms, err := room.CalculateRoomPermissions(req)
	if err != nil {
		log.L.Errorf("%v", err.Error())
		log.L.Infof("%s", err.Stack)
	}
	log.L.Infof("%+v", perms)

	//router.Start(port)
}
