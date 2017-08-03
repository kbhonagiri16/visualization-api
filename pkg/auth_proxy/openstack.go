package proxy

import (
	"fmt"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"github.com/kbhonagiri16/visualization-client"
	"github.com/shuaiming/middlewares"
	"net/http"
	"time"
	"visualization-api/pkg/grafanaclient"

	log "visualization-api/pkg/logging"
)

var (
	// DefaultOpenStackGrafanaRolesMapping default roles mapping
	DefaultOpenStackGrafanaRolesMapping = map[string]string{"admin": GrafanaRoleEditor,
		"Member": GrafanaRoleReadOnlyEditor}
)
var visualizationEndpointURL = ""

// InvalidToken error
var InvalidToken = "InvalidToken"

// OpenstackConfigs for getting openstack token
type OpenstackConfigs struct {
	OpenstackEndpoint string
	Username          string
	Password          string
	Domain            string
	Project           string
}

// OpenStackAuthHandler middleware for handling authentication via Keystone
type OpenStackAuthHandler struct {
	loginPage       []byte
	grafanaStateTTL int
	grafanaEndpoint string
	vclient         *client.VisualizationClient
	expiresAt       int64
	openstackConfs  OpenstackConfigs
	rolesMapping    map[string]string
}

// GetToken return openstack token
func GetToken(openstackConfs OpenstackConfigs) (string, int64, error) {
	// Authenticate with username and password
	authOpts := gophercloud.AuthOptions{
		IdentityEndpoint: openstackConfs.OpenstackEndpoint,
		Username:         openstackConfs.Username,
		Password:         openstackConfs.Password,
		DomainName:       openstackConfs.Domain,
	}

	provider, err := openstack.AuthenticatedClient(authOpts)
	if err != nil {
		return InvalidToken, 0, err
	}

	clientIdentity, err := openstack.NewIdentityV3(provider, gophercloud.EndpointOpts{})
	if err != nil {
		return InvalidToken, 0, err
	}

	// define token scope
	scope := tokens.Scope{ProjectName: openstackConfs.Project, DomainName: openstackConfs.Domain}

	opts := &tokens.AuthOptions{
		IdentityEndpoint: openstackConfs.OpenstackEndpoint,
		Username:         openstackConfs.Username,
		Password:         openstackConfs.Password,
		DomainName:       openstackConfs.Domain,
		Scope:            scope,
		AllowReauth:      false,
	}
	token, err := tokens.Create(clientIdentity, opts).ExtractToken()
	if err != nil {
		return InvalidToken, 0, err
	}
	openstackToken := token.ID
	expiresAt := token.ExpiresAt.UnixNano() / int64(time.Millisecond)
	return openstackToken, expiresAt, err
}

// NewOpenStackAuthHandler returns OpenStackAuthHandler
func NewOpenStackAuthHandler(loginPage []byte, grafanaStateTTL int, visualizationEndpoint string, grafanaEndpoint string, openstackConfs OpenstackConfigs, rolesMapping map[string]string) (*OpenStackAuthHandler, error) {
	visualizationEndpointURL = visualizationEndpoint
	openstackToken, expiresAt, errors := GetToken(openstackConfs)
	vclient, err := client.NewVisualizationClient(visualizationEndpoint, http.Client{}, openstackToken)
	if errors != nil {
		log.Logger.Debugf("Error during getting token err: %s", errors)
		return &OpenStackAuthHandler{loginPage: loginPage, grafanaStateTTL: grafanaStateTTL, grafanaEndpoint: grafanaEndpoint, vclient: vclient, expiresAt: expiresAt, openstackConfs: openstackConfs, rolesMapping: DefaultOpenStackGrafanaRolesMapping}, errors
	}
	if rolesMapping == nil {
		return &OpenStackAuthHandler{loginPage: loginPage,
			grafanaStateTTL: grafanaStateTTL, grafanaEndpoint: grafanaEndpoint, vclient: vclient, expiresAt: expiresAt, openstackConfs: openstackConfs, rolesMapping: DefaultOpenStackGrafanaRolesMapping}, err
	}
	return &OpenStackAuthHandler{loginPage: loginPage,
		grafanaStateTTL: grafanaStateTTL, grafanaEndpoint: grafanaEndpoint, vclient: vclient, expiresAt: expiresAt, openstackConfs: openstackConfs, rolesMapping: rolesMapping}, err
}

func (oh *OpenStackAuthHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	sess := middlewares.GetSession(r)
	log.Logger.Debugf("Session values for request are %v", sess.Values)

	// Validate Token
	timeNow := time.Now().UnixNano() / int64(time.Millisecond)
	if oh.expiresAt < timeNow {
		authHandler, err := NewOpenStackAuthHandler(oh.loginPage, oh.grafanaStateTTL, oh.grafanaEndpoint, visualizationEndpointURL, oh.openstackConfs, oh.rolesMapping)
		if err != nil {
			log.Logger.Debugf("Error during getting openstack token err: %s", err)
			return
		}
		authHandler.vclient = oh.vclient
	}

	if r.RequestURI == "/auth/openstack" {
		if r.Method == http.MethodGet {
			r.Header.Set("Content-Type", "text/html")
			_, err := rw.Write(oh.loginPage)
			if err != nil {
				log.Logger.Errorf("Error during writing response err: %s", err)
			}
			return

		} else if r.Method == http.MethodPost {

			username := r.FormValue("username")
			password := r.FormValue("password")

			log.Logger.Debugf("%s is setting as '%s'", SessionUsername, username)

			sess.Values[SessionUsername] = username
			sess.Values[SessionPassword] = password

			// Get the user by its name if exists
			userGet, err := oh.vclient.GetUserName(username)
			if err != nil {
				log.Logger.Errorf("Error during getting User by Name err: %s", err)
				return
			}
			user := client.User{}
			var orgName string
			var role string
			var exists bool
			if user == userGet {
				role = GrafanaRoleViewer
				// If user does not exists add it to main org with viewer role
				orgName = "Main Org."
				exists = false
			} else {
				log.Logger.Debugf("User exists in grafana")

				// Check if openstack credentials are correct
				ok, errors := oh.authenticate(username)
				if errors != nil {
					log.Logger.Infof("User %s is not authenticated. Due to err: %s", username, errors)
					http.Redirect(rw, r, "/auth/openstack", http.StatusInternalServerError)
				}

				if !ok {
					log.Logger.Infof("User %s is not authenticated", username)
					http.Redirect(rw, r, "/auth/openstack", http.StatusForbidden)
				}
				log.Logger.Debugf("Openstack User authenticated successfully")

				// Check if grafana credentials are correct
				okGrafana, Gerr := oh.authenticateGrafana(username, password, oh.grafanaEndpoint)
				if Gerr != nil {
					log.Logger.Infof("Grafana User %s is not authenticated. Due to err: %s", username, Gerr)
					http.Redirect(rw, r, "/auth/openstack", http.StatusInternalServerError)
				}

				if !okGrafana {
					log.Logger.Infof("Grafana User %s is not authenticated", username)
					http.Redirect(rw, r, "/auth/openstack", http.StatusForbidden)
				}
				log.Logger.Debugf("Grafana User authenticated successfully")

				// If user exists get the organizationID
				users, Uerr := oh.vclient.GetUserID(userGet.UserID)
				if Uerr != nil {
					log.Logger.Errorf("Error with getting User with ID: %s: %s", userGet.UserID, Uerr)
					return
				}

				// Get Organization name
				orgs, Oerr := oh.vclient.GetOrganizationID(users.OrgID)
				if Oerr != nil {
					log.Logger.Errorf("Error with getting Organization with ID: %s: %s", users.OrgID, Oerr)
					return
				}
				orgName = orgs.Name

				// Get user role
				userDetails, errID := oh.vclient.GetOrganizationUserID(users.OrgID, userGet.UserID)
				if errID != nil {
					log.Logger.Errorf("Error with getting user role with ID %s: %s", userGet.UserID, errID)
					return
				}
				role = userDetails.Role
				exists = true

			}
			sess.Values[GrafanaUpdateCommandSessionKey], err = oh.getGrafanaUpdateCommand(username, orgName, role, exists)
			sess.Values[UserExists] = exists
			sess.Values[OrgAndUserStateExpiresAt] = time.Now().
				Add(time.Duration(oh.grafanaStateTTL) * time.Second).
				Format(TimeFormat)
			if err != nil {
				log.Logger.Errorf("Can't create GafanaUpdateCommand for user %s err: %s", username, err)
			}

			//saving cookies/session
			err = sess.Save(r, rw)
			if err != nil {
				log.Logger.Errorf("Error during updating session err: %s", err)
				http.Error(rw, "Internal error", http.StatusInternalServerError)
				return
			}

			//We are good now 302 redirect
			http.Redirect(rw, r, "/", http.StatusFound)
			return

		} else {
			http.Error(rw, "Unexpected method", http.StatusBadRequest)
			return
		}

	}
	if data, ok := sess.Values[SessionUsername]; ok {
		// looks like user already authenticated, let us check how fresh
		// is Grafana state
		username := fmt.Sprintf("%s", data)

		if _, ok = sess.Values[OrgAndUserStateExpiresAt]; !ok {
			log.Logger.Errorf("%s key expected in session", OrgAndUserStateExpiresAt)
			http.Error(rw, "Internal error", http.StatusInternalServerError)
			return
		}

		gTTL := sess.Values[OrgAndUserStateExpiresAt]

		t, err := time.Parse(TimeFormat, fmt.Sprintf("%s", gTTL))
		if err != nil {
			log.Logger.Errorf("Can't parse time %s", gTTL)
			http.Error(rw, "Internal error", http.StatusInternalServerError)
			return
		}

		if time.Now().After(t) {
			// grafana data is outdated let us refresh if
			//TODO(illia) looks like code duplication. Should be refactored
			sess.Values[GrafanaUpdateCommandSessionKey], err = oh.getGrafanaUpdateCommand(username, "Main Org.", GrafanaRoleViewer, true)
			sess.Values[OrgAndUserStateExpiresAt] = time.Now().
				Add(time.Duration(oh.grafanaStateTTL) * time.Second).
				Format(TimeFormat)

			if err != nil {
				log.Logger.Errorf("Can't create GafanaUpdateCommand for user %s. err: %s", username, err)
			}
			//saving cookies/session
			err = sess.Save(r, rw)
			if err != nil {
				log.Logger.Errorf("Error during updating session err: %s", err)
				http.Error(rw, "Internal error", http.StatusInternalServerError)
				return
			}
		}

		log.Logger.Debugf("OpenStack user is defined in session as %s", data)
		next(rw, r)
		return
	}
	//let user enter credentials
	http.Redirect(rw, r, "/auth/openstack", http.StatusFound)
	return
}

func (oh *OpenStackAuthHandler) getGrafanaUpdateCommand(user string, org string, role string, exists bool) (GrafanaUpdateCommand, error) {
	return GrafanaUpdateCommand{
		exists,
		User{
			Login: user,
		},
		[]Organization{Organization{org, role}},
	}, nil
}

func (oh *OpenStackAuthHandler) authenticate(user string) (bool, error) {
	//TODO implement it
	return true, nil
}

func (oh *OpenStackAuthHandler) authenticateGrafana(user string, password string, url string) (bool, error) {
	//TODO implement it
	grafanaSession, err := grafanaclient.NewSession(user, password, url)
	if err != nil {
		return false, err
	}
	err = grafanaSession.DoLogon()
	if err != nil {
		return false, err
	}
	return true, nil
}
