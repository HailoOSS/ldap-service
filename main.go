package main

import (
	"time"

	log "github.com/cihub/seelog"
	"github.com/hailooss/service/config"

	service "github.com/hailooss/platform/server"

	"github.com/hailooss/ldap-service/handler"

	loginproto "github.com/hailooss/ldap-service/proto/login"
	readusersproto "github.com/hailooss/ldap-service/proto/readusers"
)

func main() {
	defer log.Flush()

	service.Name = "com.hailooss.service.ldap"
	service.Description = "This service acts as a proxy between the h2 login service and an LDAP server."
	service.Version = ServiceVersion
	service.Source = "github.com/hailooss/ldap-service"
	service.OwnerTeam = "h2o"

	service.Init()

	config.WaitUntilLoaded(time.Second * 2)

	// Setup dependencies
	handlers := handler.New()

	service.Register(&service.Endpoint{
		Name:             "login",
		Mean:             200,
		Upper95:          400,
		Handler:          handlers.Login,
		RequestProtocol:  new(loginproto.Request),
		ResponseProtocol: new(loginproto.Response),
		Authoriser:       service.OpenToTheWorldAuthoriser(),
	})

	service.Register(&service.Endpoint{
		Name:             "readusers",
		Mean:             500,
		Upper95:          800,
		Handler:          handlers.ReadUsers,
		RequestProtocol:  new(readusersproto.Request),
		ResponseProtocol: new(readusersproto.Response),
		Authoriser:       service.RoleAuthoriser([]string{"ADMIN"}),
	})

	service.Run()
}
