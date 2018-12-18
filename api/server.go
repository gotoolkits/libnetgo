package api

import (
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"html/template"
	"time"
)

var (
	sHost = "18081"
)

func ServerRun() {
	e := echo.New()
	e.HideBanner = true

	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob("web/web.htm")),
	}
	e.Renderer = renderer

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.HEAD, echo.PUT, echo.POST},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	e.Static("/", "web")
	e.GET("/ws", fnTcp)

	//self running status for monitor
	e.GET("/health", fnHealthCheck)
	e.GET("/status", fnStatus)
	e.GET("/info", fnInfo)

	e.GET("/api/getconns", FnGetConns)
	e.GET("/api/getlconns", FnGetLocalConns)
	e.GET("/api/getrconns", FnGetRemoteConns)
	e.GET("/api/sniffon", FnSniffOn)
	e.GET("/api/sniffoff", FnSniffOff)

	e.POST("/api/sniff", FnSniffStart)
	svrstus.Stime = time.Now().Format("2006-01-02 15:04:05")

	e.Logger.Fatal(e.Start(":" + sHost))
}
