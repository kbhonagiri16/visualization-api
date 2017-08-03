// Copyright Mirantis.Inc 2017.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package grafanaclient provide a simple API to manage Grafana 4.0 DataSources and Dashboards in Go.
// It's using Grafana 4.0 REST API.
// Credits https://github.com/adejoux/grafanaclient Alain Dejoux <adejoux@djouxtech.net>.
package grafanaclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"time"
)

const timeout = 5
const grafanaOrgHeader = "X-Grafana-Org-Id"

// SessionInterface Interface with all method definations
type SessionInterface interface {
	DoLogon() error
	GetOrCreateOrgByName(string) (*OrgID, error)
	CreateDataSource(DataSource) error
	GetDataSourceName(string) (DataSource, error)
	DeleteDataSource(int) error
	GetDataSourceList() ([]DataSource, error)
	GetDataSourceListID(int) (DataSource, error)
	GetUsers() ([]User, error)
	GetUserName(string) (User, error)
	GetUserID(int) (User, error)
	CreateUser(AdminCreateUser) error
	DeleteUser(int) error
	GetOrganizations() ([]OrgList, error)
	CreateOrganization(Org) error
	GetOrganizationID(int) (OrgList, error)
	DeleteOrganization(int) error
	GetOrganizationUsers(int) ([]OrgUserList, error)
	CreateOrganizationUser(int, CreateOrganizationUser) error
	UploadDashboard([]byte, string, bool) (string, error)
	DeleteDashboard(string, string) error
	DeleteOrganizationUser(int, int) error
}

// GrafanaError is a error structure to handle error messages in this library
type GrafanaError struct {
	Response    *http.Response
	Description string
}

// A GrafanaMessage contains the json error message received when http request failed
type GrafanaMessage struct {
	Message string `json:"message"`
}

// Exists Error
type Exists struct{}

// NotFound Error
type NotFound struct{}

func (e Exists) Error() string {
	return "name taken"
}

func (e NotFound) Error() string {
	return "not found"
}

// Error generate a text error message.
// If Code is zero, we know it's not a http error.
func (h GrafanaError) Error() string {
	if h.Response.StatusCode != 0 {
		return fmt.Sprintf("HTTP %d: %s", h.Response.StatusCode, h.Description)
	}
	return fmt.Sprintf("ERROR: %s", h.Description)
}

// Session contains user credentials, url and a pointer to http client session.
type Session struct {
	client   *http.Client
	User     string
	Password string
	url      string
}

// A Login contains the json structure of Grafana authentication request
type Login struct {
	User     string `json:"user"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// A DataSource contains the json structure of Grafana DataSource
type DataSource struct {
	ID                int    `json:"ID"`
	OrgID             int    `json:"orgID"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	Access            string `json:"access"`
	URL               string `json:"url"`
	Password          string `json:"password"`
	User              string `json:"user"`
	Database          string `json:"database"`
	BasicAuthUser     string `json:"basicAuthUser"`
	BasicAuthPassword string `json:"basicAuthPassword"`
	BasicAuth         bool   `json:"basicAuth"`
	IsDefault         bool   `json:"isDefault"`
}

// OrgUserList Get Users in organization
type OrgUserList struct {
	OrgID  int    `json:"orgID"`
	UserID int    `json:"userID"`
	Login  string `json:"login"`
	Role   string `json:"role"`
	Email  string `json:"email"`
}

// CreateOrganizationUser create user in organization
type CreateOrganizationUser struct {
	Login    string `json:"login"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Name     string `json:"name"`
	Password string `json:"password" binding:"Required"`
}

// OrgID Org by ID List
type OrgID struct {
	ID      int    `json:"ID"`
	Name    string `json:"name"`
	Address AddressJSON
}

// AddressJSON has details of organization
type AddressJSON struct {
	Address1 string `json:"address1"`
	Address2 string `json:"address2"`
	City     string `json:"city"`
	ZipCode  string `json:"zipCode"`
	State    string `json:"state"`
	Country  string `json:"country"`
}

// OrgList Get organization list
type OrgList struct {
	ID   int    `json:"ID"`
	Name string `json:"name"`
}

// Org Create organization
type Org struct {
	Name string `json:"name"`
}

// OrgUsers List of all users in organization
type OrgUsers struct {
	OrgID  string `json:"orgID"`
	UserID string `json:"userID"`
	Email  string `json:"email"`
	Login  string `json:"login"`
	Role   string `json:"role"`
}

// AdminCreateUser Creates User
type AdminCreateUser struct {
	Email    string `json:"email"`
	Login    string `json:"login"`
	Name     string `json:"name"`
	Password string `json:"password" binding:"Required"`
}

// User gets Users List
type User struct {
	ID    int    `json:"ID"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Login string `json:"login"`
	OrgID int    `json:"orgID"`
}

// NewSession It returns a Session struct pointer.
func NewSession(user string, password string, url string) (*Session, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &Session{client: &http.Client{Jar: jar, Timeout: time.Second * timeout}, User: user, Password: password, url: url}, nil
}

func (s *Session) reauth() bool {
	err := s.DoLogon()
	return err == nil
}

// httpRequest handle the request to Grafana server.
//It returns the response body and a error if something went wrong
func (s *Session) httpRequest(method string, url string, body io.Reader) (result io.Reader, err error) {
	return s.doHTTPRequest(method, url, body, nil)
}

func (s *Session) httpRequestWithOrgHeader(method, url, orgID string, body io.Reader) (
	result io.Reader, err error) {
	return s.doHTTPRequest(method, url, body, &map[string]string{grafanaOrgHeader: orgID})
}

func (s *Session) doHTTPRequest(method, url string, body io.Reader,
	additionalHeaders *map[string]string) (result io.Reader, err error) {

	// copy of original reader is taken, because on 401 reauth is performed
	// and request is repeated after authentication
	var bodyOrigReader io.Reader
	var bodyCopyReader io.Reader
	if body != nil {
		bodyBuffer, _ := ioutil.ReadAll(body)
		bodyOrigReader = bytes.NewBuffer(bodyBuffer)
		bodyCopyReader = bytes.NewBuffer(bodyBuffer)
	}
	request, err := http.NewRequest(method, url, bodyOrigReader)
	if err != nil {
		return result, err
	}
	request.Header.Set("Content-Type", "application/json")
	if additionalHeaders != nil {
		for headerName, headerValue := range *additionalHeaders {
			request.Header.Set(headerName, headerValue)
		}
	}

	response, err := s.client.Do(request)
	if err != nil {
		return result, err
	}

	//	defer response.Body.Close()
	if response.StatusCode != 200 {
		if response.StatusCode == 401 {
			if s.reauth() {
				return s.doHTTPRequest(method, url, bodyCopyReader, additionalHeaders)
			}
		}
		dec := json.NewDecoder(response.Body)
		var gMess GrafanaMessage
		err := dec.Decode(&gMess)
		if err != nil {
			return result, err
		}

		return result, GrafanaError{response, gMess.Message}
	}
	return response.Body, nil
}

// DoLogon uses  a new http connection using the credentials stored in the Session struct.
// It returns a error if it cannot perform the login.
func (s *Session) DoLogon() (err error) {
	reqURL := s.url + "/login"

	login := Login{User: s.User, Password: s.Password}
	jsonStr, err := json.Marshal(login)
	if err != nil {
		return
	}

	_, err = s.httpRequest("POST", reqURL, bytes.NewBuffer(jsonStr))

	return
}

// CreateDataSource creates a Grafana DataSource.
// It take a DataSource struct in parameter.
// It returns a error if it cannot perform the creation.
func (s *Session) CreateDataSource(ds DataSource) (err error) {
	reqURL := s.url + "/api/datasources"

	jsonStr, err := json.Marshal(ds)
	if err != nil {
		return
	}

	_, err = s.httpRequest("POST", reqURL, bytes.NewBuffer(jsonStr))

	return
}

// GetDataSourceName get a existing DataSource by name.
// It return a DataSource struct.
// It returns a error if a problem occurs when trying to retrieve the DataSource.
func (s *Session) GetDataSourceName(name string) (ds DataSource, err error) {
	dslist, err := s.GetDataSourceList()
	if err != nil {
		return
	}

	for _, elem := range dslist {
		if elem.Name == name {
			ds = elem
		}
	}
	return
}

// DeleteDataSource deletes a Grafana DataSource.
// It take a existing DataSource struct in parameter.
// It returns a error if it cannot perform the deletion.
func (s *Session) DeleteDataSource(ID int) (err error) {

	reqURL := fmt.Sprintf("%s/api/datasources/%d", s.url, ID)

	jsonStr, err := json.Marshal(ID)
	if err != nil {
		return
	}

	_, err = s.httpRequest("DELETE", reqURL, bytes.NewBuffer(jsonStr))

	return
}

// GetDataSourceList return a list of existing Grafana DataSources.
// It return a array of DataSource struct.
// It returns a error if it cannot get the DataSource list.
func (s *Session) GetDataSourceList() (ds []DataSource, err error) {
	reqURL := s.url + "/api/datasources"

	body, err := s.httpRequest("GET", reqURL, nil)
	if err != nil {
		return
	}
	dec := json.NewDecoder(body)
	err = dec.Decode(&ds)
	return
}

// GetDataSourceListID by ID returns single Grafana DataSources.
// It return a array of DataSource struct.
// It returns a error if it cannot get the DataSource list.
func (s *Session) GetDataSourceListID(ID int) (ds DataSource, err error) {
	reqURL := fmt.Sprintf("%s/api/datasources/%d", s.url, ID)

	body, err := s.httpRequest("GET", reqURL, nil)
	if err != nil {
		return
	}
	dec := json.NewDecoder(body)
	err = dec.Decode(&ds)
	return
}

// GetUsers returns list of users
func (s *Session) GetUsers() (user []User, err error) {
	reqURL := s.url + "/api/users"
	body, err := s.httpRequest("GET", reqURL, nil)

	if err != nil {
		return
	}
	dec := json.NewDecoder(body)
	err = dec.Decode(&user)
	return
}

// GetUserName returns user by Name
func (s *Session) GetUserName(name string) (user User, err error) {
	users, err := s.GetUsers()
	if err != nil {
		return
	}

	for _, elem := range users {
		if elem.Name == name {
			user = elem
		}
	}
	return
}

// GetUserID Get User by ID
func (s *Session) GetUserID(ID int) (user User, err error) {
	reqURL := fmt.Sprintf("%s/api/users/%d", s.url, ID)
	body, err := s.httpRequest("GET", reqURL, nil)

	if err != nil {
		switch err.(type) {
		case GrafanaError:
			if err.(GrafanaError).Response.StatusCode == 500 {
				err.(GrafanaError).Response.StatusCode = 404
				return User{}, NotFound{}
			}
			return User{}, err
		default:
			return User{}, err
		}
	}
	dec := json.NewDecoder(body)
	err = dec.Decode(&user)
	return
}

// CreateUser creates a user
func (s *Session) CreateUser(user AdminCreateUser) (err error) {
	reqURL := s.url + "/api/admin/users"
	jsonStr, err := json.Marshal(user)
	if err != nil {
		return
	}

	_, err = s.httpRequest("POST", reqURL, bytes.NewBuffer(jsonStr))

	if err != nil {
		switch err.(type) {
		case GrafanaError:
			if err.(GrafanaError).Response.StatusCode == 500 {
				err.(GrafanaError).Response.StatusCode = 404
				return Exists{}
			}
			return err
		default:
			return err
		}
	}

	return
}

// DeleteUser Delete the user with given id
func (s *Session) DeleteUser(ID int) (err error) {
	reqURL := fmt.Sprintf("%s/api/admin/users/%d", s.url, ID)
	jsonStr, err := json.Marshal(ID)
	if err != nil {
		return
	}

	_, err = s.httpRequest("DELETE", reqURL, bytes.NewBuffer(jsonStr))

	return
}

// GetOrganizations returns list of organizations
func (s *Session) GetOrganizations() (org []OrgList, err error) {
	reqURL := s.url + "/api/orgs"
	body, err := s.httpRequest("GET", reqURL, nil)

	if err != nil {
		return
	}

	dec := json.NewDecoder(body)
	err = dec.Decode(&org)
	if err != nil {
		return
	}
	return
}

// CreateOrganization creates a organization
func (s *Session) CreateOrganization(org Org) (err error) {
	reqURL := s.url + "/api/orgs"
	jsonStr, err := json.Marshal(org)
	if err != nil {
		return
	}

	_, err = s.httpRequest("POST", reqURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		switch err.(type) {
		case GrafanaError:
			if err.(GrafanaError).Response.StatusCode == 400 {
				err.(GrafanaError).Response.StatusCode = 409
				return Exists{}
			}
			return err
		default:
			return err
		}
	}

	return
}

func (s *Session) getOrgByName(name string) (*OrgID, error) {
	reqURL := fmt.Sprintf("%s/api/orgs/name/%s", s.url, name)
	body, err := s.httpRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	orgID := &OrgID{}
	dec := json.NewDecoder(body)
	err = dec.Decode(orgID)
	if err != nil {
		return nil, err
	}

	return orgID, nil
}

// GetOrCreateOrgByName makes sure that organization exists and returns it's data with id
func (s *Session) GetOrCreateOrgByName(name string) (*OrgID, error) {
	// try to get organization with provided name
	org, err := s.getOrgByName(name)
	if err != nil {
		{
			switch err.(type) {
			case GrafanaError:
				if err.(GrafanaError).Response.StatusCode == 404 {
					return s.CreateOrg(Org{name})
				}
				return nil, err
			default:
				return nil, err
			}
		}
	}
	return org, err
}

// CreateOrg creates a organization
func (s *Session) CreateOrg(org Org) (orgID *OrgID, err error) {
	reqURL := s.url + "/api/orgs"
	jsonStr, err := json.Marshal(org)
	if err != nil {
		return
	}
	body, err := s.httpRequest("POST", reqURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}

	var response struct {
		OrgID   int    `json:"orgId"`
		Message string `json:"message"`
	}
	dec := json.NewDecoder(body)
	err = dec.Decode(&response)
	orgID = &OrgID{}
	orgID.ID = response.OrgID
	orgID.Name = org.Name
	return
}

// GetOrganizationID Get Org by ID
func (s *Session) GetOrganizationID(OrgID int) (orgID OrgList, err error) {
	reqURL := fmt.Sprintf("%s/api/orgs/%d", s.url, OrgID)
	body, err := s.httpRequest("GET", reqURL, nil)

	if err != nil {
		switch err.(type) {
		case GrafanaError:
			if err.(GrafanaError).Response.StatusCode == 404 {
				return OrgList{}, NotFound{}
			}
			return OrgList{}, err
		default:
			return OrgList{}, err
		}
	}
	dec := json.NewDecoder(body)
	err = dec.Decode(&orgID)
	return
}

// DeleteOrganization Delete the organization with given id
func (s *Session) DeleteOrganization(ID int) (err error) {
	reqURL := fmt.Sprintf("%s/api/orgs/%d", s.url, ID)
	jsonStr, err := json.Marshal(ID)
	if err != nil {
		return
	}

	_, err = s.httpRequest("DELETE", reqURL, bytes.NewBuffer(jsonStr))

	return
}

// GetOrganizationUsers gets Users in Organisation
func (s *Session) GetOrganizationUsers(ID int) (org []OrgUserList, err error) {
	reqURL := fmt.Sprintf("%s/api/orgs/%d/users", s.url, ID)
	body, err := s.httpRequest("GET", reqURL, nil)

	if err != nil {
		switch err.(type) {
		case GrafanaError:
			if err.(GrafanaError).Response.StatusCode == 404 {
				return nil, NotFound{}
			}
			return nil, err
		default:
			return nil, err
		}
	}
	dec := json.NewDecoder(body)
	err = dec.Decode(&org)
	return
}

// CreateOrganizationUser Add User in Organisation
func (s *Session) CreateOrganizationUser(OrgID int, user CreateOrganizationUser) (err error) {
	// Create a user using Admin api and then add that user to organization
	userCreate := AdminCreateUser{}
	userCreate.Login = user.Login
	userCreate.Email = user.Email
	userCreate.Name = user.Name
	userCreate.Password = user.Password

	// Create user
	err = s.CreateUser(userCreate)
	if err != nil {
		switch err.(type) {
		case Exists:
			return Exists{}
		default:
			return err
		}
	}

	var orguser struct {
		LoginOrEmail string `json:"loginOrEmail"`
		Role         string `json:"role"`
	}

	orguser.LoginOrEmail = user.Login
	orguser.Role = user.Role

	reqURL := fmt.Sprintf("%s/api/orgs/%d/users", s.url, OrgID)
	jsonStr, err := json.Marshal(orguser)
	if err != nil {
		return
	}

	_, err = s.httpRequest("POST", reqURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		switch err.(type) {
		case GrafanaError:
			if err.(GrafanaError).Response.StatusCode == 400 {
				err.(GrafanaError).Response.StatusCode = 409
				return Exists{}
			}
			return err
		default:
			return err
		}
	}

	return
}

// DeleteOrganizationUser Delete User in Organisation
func (s *Session) DeleteOrganizationUser(userID int, orgID int) (err error) {
	// Deleting the user through admin api deletes that user from organization
	reqURL := fmt.Sprintf("%s/api/orgs/%d/users/%d", s.url, orgID, userID)
	var ID struct {
		UserID int `json:"userID"`
		OrgID  int `json:"orgID"`
	}
	ID.UserID = userID
	ID.OrgID = orgID
	jsonStr, err := json.Marshal(ID)
	if err != nil {
		return
	}

	_, err = s.httpRequest("DELETE", reqURL, bytes.NewBuffer(jsonStr))

	return
}

// UploadDashboard upload a new Dashboard.
func (s *Session) UploadDashboard(dashboard []byte, orgID string, overwrite bool) (
	slug string, err error) {
	reqURL := s.url + "/api/dashboards/db"

	var content struct {
		Dashboard map[string]interface{} `json:"dashboard"`
		Overwrite bool                   `json:"overwrite"`
	}

	err = json.Unmarshal(dashboard, &content.Dashboard)
	if err != nil {
		return
	}
	content.Overwrite = overwrite
	jsonStr, err := json.Marshal(content)
	if err != nil {
		return
	}

	body, err := s.httpRequestWithOrgHeader("POST", reqURL, orgID, bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	var result struct {
		Slug    string `json:"slug"`
		Status  string `json:"success"`
		Version int    `json:"version"`
	}
	dec := json.NewDecoder(body)
	err = dec.Decode(&result)
	if err != nil {
		return "", err
	}
	return result.Slug, nil
}

// DeleteDashboard delete a Grafana Dashboard.
func (s *Session) DeleteDashboard(slug, orgID string) (err error) {
	reqURL := fmt.Sprintf("%s/api/dashboards/db/%s", s.url, slug)
	_, err = s.httpRequestWithOrgHeader("DELETE", reqURL, orgID, nil)
	return
}
