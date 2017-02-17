package handler

import (
	"fmt"

	"github.com/hailooss/protobuf/proto"
	goldap "gopkg.in/ldap.v2"

	"github.com/hailooss/platform/errors"
	"github.com/hailooss/platform/server"

	"github.com/hailooss/ldap-service/ldap"

	ldapproto "github.com/hailooss/ldap-service/proto"
	loginproto "github.com/hailooss/ldap-service/proto/login"
)

func (h Handlers) Login(req *server.Request) (proto.Message, errors.Error) {
	request := req.Data().(*loginproto.Request)

	ldapConn, err := ldap.Connect()
	if err != nil {
		return nil, errors.InternalServerError(
			server.Name+".login.ldap_connect",
			fmt.Sprintf("Error attempting to connect to the LDAP server: %s", err),
		)
	}
	defer ldapConn.Close()

	// Verify the username + password
	if err := ldap.BindUser(ldapConn, request.GetUsername(), request.GetPassword()); err != nil {
		// Check error codes
		switch {
		case goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials):
			return nil, errors.BadRequest(server.Name+".login.invalid_credentials", "Invalid Credentials")
		default:
			return nil, errors.InternalServerError(
				server.Name+".login.ldap_error",
				fmt.Sprintf("Error attempting to talk to the LDAP server: %s", err),
			)
		}
	}

	// Search for the users details
	user, err := ldap.ReadUser(ldapConn, request.GetUsername())
	if err == ldap.ErrUserNotFound {
		return nil, errors.NotFound(server.Name+".login.notfound", "User not found")
	} else if err != nil {
		return nil, errors.InternalServerError(
			server.Name+".login.search_error",
			fmt.Sprintf("Error attempting to talk to the LDAP server: %s", err),
		)
	}

	// Check if the password has expired (default age to 90d)
	if user.HasPasswordExpired() {
		return nil, errors.Forbidden(server.Name+".login.passwordexpired", "Password has expired")
	}

	response := &loginproto.Response{
		User: &ldapproto.User{
			UserID:   proto.String(user.UserID),
			Username: proto.String(user.Username),
			Roles:    user.Roles,
			Groups:   user.Groups,
		},
	}

	return response, nil
}
