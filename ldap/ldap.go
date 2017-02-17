package ldap

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/ldap.v2"

	"github.com/hailooss/service/config"
	"github.com/hailooss/ldap-service/domain"
)

var (
	ErrUserNotFound = fmt.Errorf("User not found")
)

// BindAdmin binds as a read-only LDAP user which is to be used for searching
// the LDAP directory.
func BindAdmin(c *ldap.Conn) error {
	credentials, err := config.AtPath("hailo", "service", "ldap", "credentials").Decrypt()
	if err != nil {
		return err
	}

	username := credentials.AtPath("username").AsString("")
	password := credentials.AtPath("password").AsString("")

	adminBindQuery := config.AtPath("hailo", "service", "ldap", "admin_bind_query").AsString("cn=%s,ou=Users,ou=System,dc=cab,dc=elasticride,dc=com")

	username = fmt.Sprintf(adminBindQuery, username)

	return c.Bind(username, password)
}

// BindAdmin binds as a read-only LDAP user which is to be used for searching
// the LDAP directory.
func BindUser(c *ldap.Conn, username, password string) error {
	userBindQuery := config.AtPath("hailo", "service", "ldap", "user_bind_query").AsString("uid=%s,ou=People,dc=cab,dc=elasticride,dc=com")

	username = fmt.Sprintf(userBindQuery, username)

	return c.Bind(username, password)
}

// SearchUser attempts to search for a given username, SearchUser also assumes
// that you have already run Bind with a valid user.
func SearchUser(c *ldap.Conn, username string) (*ldap.SearchResult, error) {
	userSearchBase := config.AtPath("hailo", "service", "ldap", "user_search_base").AsString("ou=People,dc=cab,dc=elasticride,dc=com")
	userSearchQuery := config.AtPath("hailo", "service", "ldap", "user_search_query").AsString("(uid=%s)")

	searchRequest := ldap.NewSearchRequest(
		userSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(userSearchQuery, username),
		[]string{"dn", "memberOf", "uid", "uidNumber", "pwdChangedTime"}, nil,
	)

	return c.Search(searchRequest)
}

func ReadUser(c *ldap.Conn, uid string) (*domain.User, error) {
	sr, err := SearchUser(c, uid)
	if err != nil {
		// Check error codes
		switch {
		case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
			return nil, ErrUserNotFound
		default:
			return nil, err
		}
	}

	return extractUser(sr)
}

func extractUser(sr *ldap.SearchResult) (*domain.User, error) {
	if len(sr.Entries) != 1 {
		return nil, ErrUserNotFound
	}

	entry := sr.Entries[0]

	// Extract response from search result
	user := &domain.User{}
	for _, attribute := range entry.Attributes {
		switch attribute.Name {
		case "uid":
			if len(attribute.Values) >= 1 {
				user.Username = attribute.Values[0]
			}
		case "uidNumber":
			if len(attribute.Values) >= 1 {
				user.UserID = attribute.Values[0]
			}
		case "memberOf":
			user.Groups = extractGroups(attribute.Values)
		case "roles":
			user.Roles = attribute.Values
		case "pwdChangedTime":
			if len(attribute.Values) >= 1 {
				t, err := time.Parse("20060102150405Z", attribute.Values[0])
				if err != nil {
					t = time.Now()
				}
				user.PasswordChanged = t
			}
		}
	}

	// Ensure that all fields are set
	if user.UserID == "" || user.Username == "" {
		return nil, fmt.Errorf("Missing user attributes")
	}

	// Add group roles to the users existing roles
	user.Roles = append(user.Roles, domain.ReadRolesForGroups(user.Groups)...)

	return user, nil
}

// extractGroups takes the list of values from the memberOf attribute and
// returns a list of groups.
func extractGroups(values []string) []string {
	groups := []string{}
	for _, dn := range values {
		attributes := parseDN(dn)
		if cn, ok := attributes["cn"]; ok {
			groups = append(groups, cn...)
		}
	}
	return groups
}

func parseDN(dn string) map[string][]string {
	attributes := map[string][]string{}

	rdns := strings.Split(dn, ",")
	for _, rdn := range rdns {
		parts := strings.SplitN(rdn, "=", 2)
		if len(parts) == 2 {
			key := strings.ToLower(parts[0])
			val := parts[1]

			if _, ok := attributes[key]; !ok {
				attributes[key] = []string{}
			}

			attributes[key] = append(attributes[key], val)
		}
	}

	return attributes
}
