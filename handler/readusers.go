package handler

import (
	"fmt"

	"github.com/hailooss/protobuf/proto"

	"github.com/hailooss/platform/errors"
	"github.com/hailooss/platform/server"

	"github.com/hailooss/ldap-service/ldap"

	ldapproto "github.com/hailooss/ldap-service/proto"
	readusersproto "github.com/hailooss/ldap-service/proto/readusers"
)

func (h Handlers) ReadUsers(req *server.Request) (proto.Message, errors.Error) {
	request := req.Data().(*readusersproto.Request)
	response := &readusersproto.Response{}

	ldapConn, err := ldap.Connect()
	if err != nil {
		return nil, errors.InternalServerError(
			server.Name+".login.ldap_connect",
			fmt.Sprintf("Error attempting to connect to the LDAP server: %s", err),
		)
	}
	defer ldapConn.Close()

	// Bind as an admin to allow you to read the users
	if err := ldap.BindAdmin(ldapConn); err != nil {
		return nil, errors.InternalServerError(
			server.Name+".readusers.bind", fmt.Sprintf("Error binding as admin: %s", err),
		)
	}

	for _, uid := range request.GetIds() {
		user, err := ldap.ReadUser(ldapConn, uid)
		if err == ldap.ErrUserNotFound {
			return nil, errors.NotFound(server.Name+".login.notfound", "User not found")
		} else if err != nil {
			return nil, errors.InternalServerError(
				server.Name+".login.search_error",
				fmt.Sprintf("Error attempting to talk to the LDAP server: %s", err),
			)
		}

		response.Users = append(response.Users, &ldapproto.User{
			UserID:   proto.String(user.UserID),
			Username: proto.String(user.Username),
			Roles:    user.Roles,
			Groups:   user.Groups,
		})
	}

	return response, nil
}
