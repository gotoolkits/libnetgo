package api

import (
	"github.com/gotoolkits/libnetgo/connect"
	"github.com/labstack/echo"
	"net/http"
)

type SvrStatus struct {
	Stime string `json:"start_time"`
	// UserItemMapSize    int      `json:"userItemMapSize"`
	// WanningUserMapSize int      `json:"wanningUserMapSize"`
	// ExpiredQueue       UQueue   `json:"expiredQueue"`
	// ThreeDayQueue      UQueue   `json:"3dayQueue"`
	// WeekQueue          UQueue   `json:"7dayQueue"`
	// HalfMonthQueue     UQueue   `json:"15dayQueue"`
	SyncErrUsers []string `json:"syncErrUsers"`
}

type SysInfo struct {
	AppID   string   `json:"AppID"`
	SysName string   `json:"AppName"`
	Version string   `json:"Version"`
	APIs    []string `json:"APIs"`
	Author  string   `json:"Author"`
}

var (
	svrstus SvrStatus
	uuid    = "c98bad34-e0f2-4eec-bf98-2eda26af935c"
	info    SysInfo
)

func init() {

	info = SysInfo{
		AppID:   uuid,
		SysName: "linux network analyzer",
		Version: "V1.0.1",
		APIs:    nil,
		Author:  "gotoolkits",
	}

}

func fnInfo(c echo.Context) error {
	return c.JSONPretty(http.StatusOK, info, " ")
}

func fnHealthCheck(c echo.Context) error {
	return c.String(http.StatusOK, "Success")
}

func fnStatus(c echo.Context) error {
	// staticsticsStatus()
	return c.JSONPretty(http.StatusOK, svrstus, " ")
}

func FnGetConns(c echo.Context) error {
	return c.JSONPretty(http.StatusOK, connect.GetConns("all"), " ")
}

func FnFormatNodes(c echo.Context) error {
	return c.JSONPretty(http.StatusOK, nil, " ")

}

func FnGetDownNodes(c echo.Context) error {
	return c.JSONPretty(http.StatusOK, nil, " ")
}
