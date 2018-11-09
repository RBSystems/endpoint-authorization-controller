package main

import (
	"net/http"

	"github.com/byuoitav/common"
	"github.com/byuoitav/common/log"
	"github.com/byuoitav/endpoint-authorization-controller/base"
	"github.com/byuoitav/endpoint-authorization-controller/permissions"
	"github.com/labstack/echo"
)

func main() {
	port := ":7200"
	router := common.NewRouter()

	router.POST("/authorize", authorize)

	router.Start(port)
}

func authorize(ctx echo.Context) error {
	req := base.Request{}

	//we need to get the body out
	err := ctx.Bind(&req)
	if err != nil {
		log.L.Warnf("Bad request payload: %v", err.Error())
		return ctx.String(http.StatusBadRequest, "Bad request payload, must be auth request")
	}

	perms, er := permissions.GetAuthorization(req)
	if er != nil {
		log.L.Warnf("Problem getting authorization: %v", er.Error())
		return ctx.String(http.StatusInternalServerError, "There was a problem getting the authorization, check your request and try again later.")
	}

	return ctx.JSON(http.StatusOK, perms)
}
