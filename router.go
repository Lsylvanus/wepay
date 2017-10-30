package main

import (
	"net/http"

	"github.com/labstack/echo"
)

func initRouter() {

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "wepay")
	})
	e.GET("/wepay/api", api)
	e.GET("/wepay/randnum", randNums)
	e.Logger.Fatal(e.Start(":1323"))
}
