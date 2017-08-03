package v1Api

import (
	"encoding/json"
	"strconv"
	"time"

	"visualization-api/pkg/grafanaclient"
	"visualization-api/pkg/http_endpoint/authentication"
	"visualization-api/pkg/http_endpoint/common"
	v1handlers "visualization-api/pkg/http_endpoint/v1/handlers"
	"visualization-api/pkg/logging"
)

// TokenIssueHours defines on how much hours our token would be issued
const TokenIssueHours = 3

// V1Handler is implementation of Handler interface
type V1Handler struct {
	v1handlers.V1UsersOrgs
	v1handlers.V1Visualizations
}

// AuthOpenstack uses provided keystone token to create jwt token
func (h *V1Handler) AuthOpenstack(clients *common.ClientContainer,
	clock common.ClockInterface, openstackToken string,
	secret string) ([]byte, error) {

	tokenValid, err := clients.Openstack.ValidateToken(openstackToken)
	if err != nil {
		log.Logger.Errorf("Error validating openstack Token: %s", err)
		return nil, err
	}
	if !tokenValid {
		return nil, common.InvalidOpenstackToken{}
	}

	tokenInfo, err := clients.Openstack.GetTokenInfo(openstackToken)
	if err != nil {
		log.Logger.Errorf("Error retrieving openstack Token: %s", err)
		return nil, err
	}

	expirationTime := clock.Now().Add(TokenIssueHours * time.Hour)

	grafanaOrg, err := clients.Grafana.GetOrCreateOrgByName(
		tokenInfo.ProjectName + "-" + tokenInfo.ProjectID)
	if err != nil {
		return nil, err
	}
	grafanaOrgID := strconv.Itoa(grafanaOrg.ID)

	token, err := httpAuth.JWTTokenFromParams(secret, tokenInfo.IsAdmin(),
		grafanaOrgID, expirationTime)
	if err != nil {
		return nil, err
	}

	var payload struct {
		JWT   string `json:"jwt"`
		Token struct {
			OrganizationID string    `json:"organizationId"`
			ExpiresAt      time.Time `json:"expiresAt"`
			IsAdmin        bool      `json:"isAdmin"`
		} `json:"token"`
	}

	payload.JWT = token
	payload.Token.OrganizationID = grafanaOrgID
	payload.Token.ExpiresAt = expirationTime
	payload.Token.IsAdmin = tokenInfo.IsAdmin()

	return json.Marshal(payload)
}

// GetUsers get list of users
func (h *V1Handler) GetUsers(clients *common.ClientContainer) ([]byte, error) {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return nil, err
	}
	userlist, err := clients.Grafana.GetUsers()

	if err != nil {
		return nil, err
	}
	type user struct {
		UserID string `json:"userID"`
		Name   string `json:"name"`
		Login  string `json:"login"`
		Email  string `json:"email"`
	}

	var users = make([]user, 0)
	for _, values := range userlist {
		eachUser := user{
			UserID: strconv.Itoa(values.ID),
			Name:   values.Name,
			Login:  values.Login,
			Email:  values.Email,
		}
		users = append(users, eachUser)
	}

	return json.Marshal(users)
}

// GetUserID get user details by ID
func (h *V1Handler) GetUserID(clients *common.ClientContainer, ID int) ([]byte, error) {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return nil, err
	}
	userlist, err := clients.Grafana.GetUserID(ID)
	if err != nil {
		return nil, err
	}

	var users struct {
		UserID string `json:"userID"`
		Name   string `json:"name"`
		Login  string `json:"login"`
		Email  string `json:"email"`
		OrgID  string `json:"orgID"`
	}

	users.UserID = strconv.Itoa(ID)
	users.Name = userlist.Name
	users.Login = userlist.Login
	users.Email = userlist.Email
	users.OrgID = strconv.Itoa(userlist.OrgID)

	return json.Marshal(users)
}

// DeleteUser deletes user by ID
func (h *V1Handler) DeleteUser(clients *common.ClientContainer, ID int) error {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return err
	}
	err = clients.Grafana.DeleteUser(ID)

	return err
}

// CreateUser creates user
func (h *V1Handler) CreateUser(clients *common.ClientContainer, res []byte) error {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return err
	}

	params := grafanaclient.AdminCreateUser{}
	err = json.Unmarshal(res, &params)
	if err != nil {
		log.Logger.Error(err)
		return err
	}
	err = clients.Grafana.CreateUser(params)

	return err
}

// GetOrganizations get organization details
func (h *V1Handler) GetOrganizations(clients *common.ClientContainer) ([]byte, error) {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return nil, err
	}
	orglist, err := clients.Grafana.GetOrganizations()
	if err != nil {
		return nil, err
	}

	type organization struct {
		Name           string `json:"name"`
		OrganizationID string `json:"organizationID"`
	}

	var organizations = make([]organization, 0)

	for _, values := range orglist {
		orgs := organization{
			OrganizationID: strconv.Itoa(values.ID),
			Name:           values.Name,
		}
		organizations = append(organizations, orgs)
	}

	return json.Marshal(organizations)
}

// GetOrganizationID gets organization details by ID
func (h *V1Handler) GetOrganizationID(clients *common.ClientContainer, ID int) ([]byte, error) {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return nil, err
	}
	orglist, err := clients.Grafana.GetOrganizationID(ID)
	if err != nil {
		return nil, err
	}

	var orgs struct {
		OrganizationID string `json:"organizationID"`
		Name           string `json:"name"`
	}
	orgs.OrganizationID = strconv.Itoa(orglist.ID)
	orgs.Name = orglist.Name

	return json.Marshal(orgs)
}

// DeleteOrganization delete organization by ID
func (h *V1Handler) DeleteOrganization(clients *common.ClientContainer, ID int) error {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return err
	}
	err = clients.Grafana.DeleteOrganization(ID)

	return err
}

// DeleteOrganizationUser delete user in an organization
func (h *V1Handler) DeleteOrganizationUser(clients *common.ClientContainer, userID int, orgID int) error {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return err
	}
	err = clients.Grafana.DeleteOrganizationUser(userID, orgID)

	return err
}

// GetOrganizationUsers get user detials in an organization
func (h *V1Handler) GetOrganizationUsers(clients *common.ClientContainer, ID int) ([]byte, error) {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return nil, err
	}
	orglist, err := clients.Grafana.GetOrganizationUsers(ID)
	if err != nil {
		return nil, err
	}

	type organization struct {
		OrganizationID string `json:"organizationID"`
		UserID         string `json:"userID"`
		Login          string `json:"login"`
		Role           string `json:"role"`
		Email          string `json:"email"`
	}

	var organizations = make([]organization, 0)

	for _, values := range orglist {
		orgs := organization{
			UserID:         strconv.Itoa(values.UserID),
			OrganizationID: strconv.Itoa(values.OrgID),
			Login:          values.Login,
			Role:           values.Role,
			Email:          values.Email,
		}
		organizations = append(organizations, orgs)
	}

	return json.Marshal(organizations)
}

// CreateOrganization create an organization
func (h *V1Handler) CreateOrganization(clients *common.ClientContainer, res []byte) error {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return err
	}
	params := grafanaclient.Org{}
	err = json.Unmarshal(res, &params)
	if err != nil {
		log.Logger.Error(err)
		return err
	}

	err = clients.Grafana.CreateOrganization(params)

	return err
}

// CreateOrganizationUser create a user in organization
func (h *V1Handler) CreateOrganizationUser(clients *common.ClientContainer, OrgID int, res []byte) error {
	err := clients.Grafana.DoLogon()
	if err != nil {
		v1handlers.LoginErrorCheck(err)
		return err
	}

	params := grafanaclient.CreateOrganizationUser{}
	err = json.Unmarshal(res, &params)
	if err != nil {
		log.Logger.Error(err)
		return err
	}

	err = clients.Grafana.CreateOrganizationUser(OrgID, params)

	return err
}
