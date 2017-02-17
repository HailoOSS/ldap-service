package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/ldap.v2"
)

func TestExtractGroups(t *testing.T) {
	values := []string{
		"cn=group1,ou=Groups,dc=example,dc=com",
		"cn=group2,cn=group3,ou=Groups,dc=example,dc=com",
	}
	groups := extractGroups(values)

	assert.Equal(t, []string{"group1", "group2", "group3"}, groups)
}

func TestParseDN(t *testing.T) {
	dn := "CN=Jeff Smith,OU=Sales,DC=example,DC=COM,test"
	values := parseDN(dn)

	assert.Equal(t, values["cn"], []string{"Jeff Smith"})
	assert.Equal(t, values["ou"], []string{"Sales"})
	assert.Equal(t, values["dc"], []string{"example", "COM"})
	assert.Equal(t, values["test"], []string(nil))
	assert.Equal(t, values["test2"], []string(nil))
}

func TextExtractUser_NotFound(t *testing.T) {
	sr := &ldap.SearchResult{}

	_, err := extractUser(sr)

	assert.Equal(t, ErrUserNotFound, err)
}

func TextExtractUser_ValidUser(t *testing.T) {
	sr := &ldap.SearchResult{
		Entries: []*ldap.Entry{
			&ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					ldap.NewEntryAttribute("uid", []string{"john.smith"}),
					ldap.NewEntryAttribute("uidNumber", []string{"1"}),
					ldap.NewEntryAttribute("memberOf", []string{"admin"}),
					ldap.NewEntryAttribute("roles", []string{""}),
					ldap.NewEntryAttribute("pwdChangedTime", []string{"20160101000000Z"}),
				},
			},
		},
	}

	user, err := extractUser(sr)

	assert.Nil(t, err)
	assert.Equal(t, "1", user.UserID)
	assert.Equal(t, "john.smith", user.Username)
	assert.Equal(t, []string{"admin"}, user.Groups)
	assert.Equal(t, []string{"ADMIN"}, user.Roles)
	assert.Equal(t, time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC), user.PasswordChanged)
}
