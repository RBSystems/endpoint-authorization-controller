package main

import "github.com/byuoitav/common"

func main() {
	port := ":7200"
	router := common.NewRouter()

	router.Start(port)
}
