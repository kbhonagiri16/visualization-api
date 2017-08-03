package proxy

import (
	"encoding/gob"
	"time"
)

// SessionUsername key used for storing username in request context
const SessionUsername = "USERNAME"

// OrgAndUserStateExpiresAt for cache expiration time
const OrgAndUserStateExpiresAt = "ORG_AND_USER_STATE_EXPIRES_AT"

// GrafanaUpdateCommandSessionKey key used for storing GrafanaUpdateCommand in request context
const GrafanaUpdateCommandSessionKey = "GRAFANA_UPDATE_COMMAND"

//GrafanaRoleAdmin Admin
const GrafanaRoleAdmin = "Admin"

//GrafanaRoleReadOnlyEditor ReadOnlyEditor
const GrafanaRoleReadOnlyEditor = "ReadOnlyEditor"

//GrafanaRoleEditor Editor
const GrafanaRoleEditor = "Editor"

//GrafanaRoleViewer Viewer
const GrafanaRoleViewer = "Viewer"

//UserExists Grafana
const UserExists = "Exists"

// SessionPassword key used for storing  password
const SessionPassword = "PASSWORD"

//TimeFormat used for cache expiration time representation
const TimeFormat = time.RFC3339

func init() {
	//registering of model to store in session
	gob.Register(GrafanaUpdateCommand{})
}

// GrafanaUpdateCommand model for grafana roles for user
type GrafanaUpdateCommand struct {
	Exists        bool
	User          User
	Organizations []Organization
}

// Organization model
type Organization struct {
	Name string
	Role string
}

// User model
type User struct {
	Login string
	Name  string
	Email string
}
