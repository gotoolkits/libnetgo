package api

import (
	"github.com/gotoolkits/libnetgo/connect"
	"github.com/gotoolkits/libnetgo/packet"

	"github.com/labstack/echo"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type SvrStatus struct {
	Stime      string `json:"start_time"`
	SniffStart bool   `json:"Sniff_Start"`
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

type Switch struct {
	Token string `json:"token" xml:"token" form:"token" query:"token"`
	Code  string `json:"Code" xml:"Code" form:"Code" query:"Code"`
}

var (
	svrstus SvrStatus
	uuid    = "c98bad34-e0f2-4eec-bf98-2eda26af935c"
	info    SysInfo
	HostIP  string
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
	svrstus.SniffStart = packet.Start
	return c.JSONPretty(http.StatusOK, svrstus, " ")
}

func FnGetConns(c echo.Context) error {
	return c.JSONPretty(http.StatusOK, connect.GetConns("all"), " ")
}

func FnGetLocalConns(c echo.Context) error {
	return c.JSONPretty(http.StatusOK, connect.GetConns("local"), " ")

}

func FnGetRemoteConns(c echo.Context) error {
	return c.JSONPretty(http.StatusOK, connect.GetConns("remote"), " ")
}

func FnSniffOn(c echo.Context) error {
	packet.StartNetSniff(HostIP)
	return c.JSONPretty(http.StatusOK, packet.Start, " ")
}

func FnSniffOff(c echo.Context) error {
	packet.StopNetSniff()
	return c.JSONPretty(http.StatusOK, packet.Start, " ")
}

func FnSniffStart(c echo.Context) error {
	sw := new(Switch)
	if err := c.Bind(sw); err != nil {
		log.Errorln(err)
		return c.String(http.StatusUnauthorized, "Parse_Failed")
	}

	if sw.Code == "" || sw.Token == "" {
		return c.String(http.StatusNonAuthoritativeInfo, "Args_Null")
	}
	if sw.Token != "c98bad34-e0f2-4eec-bf98-2eda26af935c" {
		return c.String(http.StatusUnauthorized, "Token_auth_failed")
	}

	if sw.Code == "1" {
		return c.String(http.StatusOK, "On")
	}
	if sw.Code == "0" {
		return c.String(http.StatusOK, "Off")
	}
	return c.String(http.StatusOK, "None")
}
