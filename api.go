package main

import (
	"github.com/labstack/echo"
	"net/http"
)

func api(c echo.Context) error {
	return c.JSON(http.StatusOK, "hello, welcome to wepay.")
}

func randNums(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderAccessControlAllowOrigin, "*")
	com := comm{Count:10}
	return c.JSON(http.StatusOK, com.GetRandNum())
}
