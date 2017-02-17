package domain

import (
	"time"

	"github.com/hailooss/service/config"
)

type User struct {
	UserID          string
	Username        string
	Groups          []string
	Roles           []string
	PasswordChanged time.Time
}

func (u *User) HasPasswordExpired() bool {
	maxPasswordAge := config.AtPath("hailo", "service", "ldap", "max_password_age").AsDuration("2160h")
	if time.Now().After(u.PasswordChanged.Add(maxPasswordAge)) {
		return true
	}

	return false
}
