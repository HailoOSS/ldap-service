package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHasPasswordExpired_true(t *testing.T) {
	// Set password changed to some time before 90d
	user := &User{
		PasswordChanged: time.Now().Add(-time.Hour * 3000),
	}

	assert.Equal(t, true, user.HasPasswordExpired())
}

func TestHasPasswordExpired_false(t *testing.T) {
	user := &User{
		PasswordChanged: time.Now(),
	}

	assert.Equal(t, false, user.HasPasswordExpired())
}
