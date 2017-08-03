package v1Apitest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"

	"visualization-api/pkg/grafanaclient"
	"visualization-api/pkg/grafanaclient/mock"
	"visualization-api/pkg/http_endpoint"
	"visualization-api/pkg/http_endpoint/common/mock"
	"visualization-api/pkg/http_endpoint/common/tests"
	"visualization-api/pkg/http_endpoint/v1"
)

const ID = 1

func TestGrafanaUsersGetHttp(t *testing.T) {
	testHelper.InitializeLogger()

	testCases := []struct {
		description      string
		secret           string
		projectID        string
		provideAuthToken bool
		expectedCode     int
	}{
		{
			description:      "make sure that handler reacts",
			secret:           "secret",
			provideAuthToken: true,
			projectID:        "project1",
			expectedCode:     200,
		},
		{

			description:      "failed authorization",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: false,
			expectedCode:     401,
		},
	}

	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		// create httpRequest object
		request, _ := http.NewRequest("GET", "/v1/admin/users", nil)
		response := httptest.NewRecorder()
		if testCase.provideAuthToken {
			testHelper.SetRequestAuthHeader(testCase.secret, testCase.projectID,
				request)
			mockedHandle.EXPECT().GetUsers(clientContainer)
		}

		endpoint.InitializeRouter(clientContainer, mockedHandle,
			testCase.secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")

	}
}

func TestGrafanaUserIDGetHttp(t *testing.T) {
	testHelper.InitializeLogger()

	testCases := []struct {
		description      string
		secret           string
		projectID        string
		provideAuthToken bool
		expectedCode     int
		provideString    bool
	}{
		{
			description:      "make sure that handler reacts",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: true,
			expectedCode:     200,
			provideString:    false,
		},
		{
			description:      "failed authorization",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: false,
			expectedCode:     401,
			provideString:    false,
		},
		{
			description:      "provide ID as string",
			secret:           "secret",
			provideAuthToken: true,
			expectedCode:     422,
			projectID:        "project1",
			provideString:    true,
		},
	}

	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		// create httpRequest object
		request, _ := http.NewRequest("GET", fmt.Sprintf("/v1/admin/users/%d", ID), nil)
		if testCase.provideString {
			request, _ = http.NewRequest("GET", fmt.Sprintf("/v1/admin/users/%s", "ID"), nil)
		}
		response := httptest.NewRecorder()

		if testCase.provideAuthToken {
			testHelper.SetRequestAuthHeader(testCase.secret, testCase.projectID,
				request)
			if !testCase.provideString {
				mockedHandle.EXPECT().GetUserID(clientContainer, ID)
			}
		}

		endpoint.InitializeRouter(clientContainer, mockedHandle,
			testCase.secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
	}
}

func TestGrafanaUsersCreateHttp(t *testing.T) {
	testHelper.InitializeLogger()

	testCases := []struct {
		description      string
		secret           string
		projectID        string
		provideAuthToken bool
		expectedCode     int
		input            grafanaclient.AdminCreateUser
		errorInput       bool
	}{
		{
			description:      "make sure that handler reacts",
			secret:           "secret",
			provideAuthToken: true,
			projectID:        "project1",
			expectedCode:     200,
			errorInput:       false,
			input:            grafanaclient.AdminCreateUser{Name: "admin", Login: "admin", Email: "admin@localhost.com", Password: "password"},
		},
		{
			description:      "missing Name and Email",
			secret:           "secret",
			provideAuthToken: true,
			projectID:        "project1",
			errorInput:       true,
			expectedCode:     500,
			input:            grafanaclient.AdminCreateUser{Login: "admin", Password: "password"},
		},
		{

			description:      "failed authorization",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: false,
			errorInput:       false,
			expectedCode:     401,
		},
	}

	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		jsonStr, err := json.Marshal(testCase.input)
		assert.Equal(t, err, nil, "no error")

		// create httpRequest object
		request, _ := http.NewRequest("POST", "/v1/admin/users", bytes.NewBuffer(jsonStr))
		request.Header.Set("Content-Type", "application/json")

		if testCase.provideAuthToken {
			testHelper.SetRequestAuthHeader(testCase.secret,
				testCase.projectID, request)
			if !testCase.errorInput {
				mockedHandle.EXPECT().CreateUser(clientContainer, jsonStr)
			}
		}

		response := httptest.NewRecorder()
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			testCase.secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")

	}
}

func TestGrafanaDeleteUserHttp(t *testing.T) {
	testHelper.InitializeLogger()

	testCases := []struct {
		description      string
		secret           string
		projectID        string
		provideAuthToken bool
		expectedCode     int
		provideString    bool
	}{
		{
			description:      "make sure that handler reacts",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: true,
			expectedCode:     200,
			provideString:    false,
		},
		{
			description:      "failed authorization",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: false,
			expectedCode:     401,
			provideString:    false,
		},
		{
			description:      "provide ID as string",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: true,
			expectedCode:     422,
			provideString:    true,
		},
	}

	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		// create httpRequest object
		request, _ := http.NewRequest("DELETE", fmt.Sprintf("/v1/admin/users/%d", ID), nil)
		if testCase.provideString {
			request, _ = http.NewRequest("DELETE", fmt.Sprintf("/v1/admin/users/%s", "ID"), nil)
		}
		response := httptest.NewRecorder()
		if testCase.provideAuthToken {
			testHelper.SetRequestAuthHeader(testCase.secret, testCase.projectID,
				request)
			if !testCase.provideString {
				mockedHandle.EXPECT().GetUserID(clientContainer, ID)
				mockedHandle.EXPECT().DeleteUser(clientContainer, ID)
			}
		}
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			testCase.secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
	}
}

func TestOrganizationsGetHttp(t *testing.T) {
	testHelper.InitializeLogger()

	testCases := []struct {
		description      string
		secret           string
		projectID        string
		provideAuthToken bool
		expectedCode     int
	}{
		{
			description:      "make sure that handler reacts",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: true,
			expectedCode:     200,
		},
		{
			description:      "failed authorization",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: false,
			expectedCode:     401,
		},
	}

	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		// create httpRequest object
		request, _ := http.NewRequest("GET", "/v1/admin/organizations", nil)
		response := httptest.NewRecorder()
		if testCase.provideAuthToken {
			testHelper.SetRequestAuthHeader(testCase.secret, testCase.projectID,
				request)
			mockedHandle.EXPECT().GetOrganizations(clientContainer)
		}
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			testCase.secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
	}
}

func TestGrafanaOrganizationIDGetHttp(t *testing.T) {
	testHelper.InitializeLogger()

	testCases := []struct {
		description      string
		secret           string
		projectID        string
		provideAuthToken bool
		expectedCode     int
		provideString    bool
	}{
		{
			description:      "make sure that handler reacts",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: true,
			expectedCode:     200,
			provideString:    false,
		},
		{
			description:      "failed authorization",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: false,
			expectedCode:     401,
			provideString:    false,
		},
		{
			description:      "provide string as ID",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: true,
			expectedCode:     422,
			provideString:    true,
		},
	}

	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		// create httpRequest object
		request, _ := http.NewRequest("GET", fmt.Sprintf("/v1/admin/organizations/%d", ID), nil)
		if testCase.provideString {
			request, _ = http.NewRequest("GET", fmt.Sprintf("/v1/admin/organizations/%s", "ID"), nil)
		}
		response := httptest.NewRecorder()

		if testCase.provideAuthToken {
			testHelper.SetRequestAuthHeader(testCase.secret, testCase.projectID,
				request)
			if !testCase.provideString {
				mockedHandle.EXPECT().GetOrganizationID(clientContainer, ID)
			}
		}

		endpoint.InitializeRouter(clientContainer, mockedHandle,
			testCase.secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
	}
}

func TestGrafanaOrganizationCreateHttp(t *testing.T) {
	testHelper.InitializeLogger()

	testCases := []struct {
		description      string
		secret           string
		projectID        string
		provideAuthToken bool
		expectedCode     int
		errorInput       bool
		input            grafanaclient.Org
	}{
		{
			description:      "make sure that handler reacts",
			secret:           "secret",
			provideAuthToken: true,
			projectID:        "project1",
			expectedCode:     200,
			errorInput:       false,
			input:            grafanaclient.Org{Name: "org1"},
		},
		{
			description:      "missing Name from parameters",
			secret:           "secret",
			provideAuthToken: true,
			projectID:        "project1",
			expectedCode:     500,
			errorInput:       true,
			input:            grafanaclient.Org{},
		},
		{

			description:      "failed authorization",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: false,
			errorInput:       false,
			expectedCode:     401,
		},
	}

	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		jsonStr, err := json.Marshal(testCase.input)
		assert.Equal(t, err, nil, "no error")

		// create httpRequest object
		request, _ := http.NewRequest("POST", "/v1/admin/organizations", bytes.NewBuffer(jsonStr))
		request.Header.Set("Content-Type", "application/json")

		if testCase.provideAuthToken {
			testHelper.SetRequestAuthHeader(testCase.secret,
				testCase.projectID, request)
			if !testCase.errorInput {
				mockedHandle.EXPECT().CreateOrganization(clientContainer,
					jsonStr)
			}
		}

		response := httptest.NewRecorder()
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			testCase.secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")

	}
}

func TestGrafanaDeleteOrganizationHttp(t *testing.T) {
	testHelper.InitializeLogger()

	testCases := []struct {
		description      string
		secret           string
		projectID        string
		provideAuthToken bool
		expectedCode     int
		provideString    bool
	}{
		{
			description:      "make sure that handler reacts",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: true,
			expectedCode:     200,
			provideString:    false,
		},
		{
			description:      "failed authorization",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: false,
			expectedCode:     401,
			provideString:    false,
		},
		{
			description:      "provide string as ID",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: true,
			expectedCode:     422,
			provideString:    true,
		},
	}

	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		// create httpRequest object
		request, _ := http.NewRequest("DELETE", fmt.Sprintf("/v1/admin/organizations/%d", ID), nil)
		if testCase.provideString {
			request, _ = http.NewRequest("DELETE", fmt.Sprintf("/v1/admin/organizations/%s", "ID"), nil)
		}
		response := httptest.NewRecorder()
		if testCase.provideAuthToken {
			testHelper.SetRequestAuthHeader(testCase.secret, testCase.projectID,
				request)
			if !testCase.provideString {
				mockedHandle.EXPECT().GetOrganizationID(clientContainer, ID)
				mockedHandle.EXPECT().DeleteOrganization(clientContainer, ID)
			}
		}
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			testCase.secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
	}
}

func TestGrafanaOrganizationUserIDGetHttp(t *testing.T) {
	testHelper.InitializeLogger()

	testCases := []struct {
		description      string
		secret           string
		projectID        string
		provideAuthToken bool
		expectedCode     int
		provideString    bool
	}{
		{
			description:      "make sure that handler reacts",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: true,
			expectedCode:     200,
			provideString:    false,
		},
		{
			description:      "failed authorization",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: false,
			expectedCode:     401,
			provideString:    false,
		},
		{
			description:      "provide string as ID",
			secret:           "secret",
			projectID:        "project1",
			provideAuthToken: true,
			expectedCode:     422,
			provideString:    true,
		},
	}

	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		// create httpRequest object
		request, _ := http.NewRequest("GET", fmt.Sprintf("/v1/admin/organizations/%d/users", ID), nil)
		if testCase.provideString {
			request, _ = http.NewRequest("GET", fmt.Sprintf("/v1/admin/organizations/%s/users", "ID"), nil)
		}
		response := httptest.NewRecorder()

		if testCase.provideAuthToken {
			testHelper.SetRequestAuthHeader(testCase.secret, testCase.projectID,
				request)
			if !testCase.provideString {
				mockedHandle.EXPECT().GetOrganizationID(clientContainer, ID)
				mockedHandle.EXPECT().GetOrganizationUsers(clientContainer, ID)
			}
		}

		endpoint.InitializeRouter(clientContainer, mockedHandle,
			testCase.secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
	}
}

func TestGrafanaDeleteOrganizationUserHttp(t *testing.T) {
	testHelper.InitializeLogger()

	testCases := []struct {
		description        string
		secret             string
		projectID          string
		provideAuthToken   bool
		expectedCode       int
		provideString      bool
		provideOrgIDString bool
	}{
		{
			description:        "make sure that handler reacts",
			secret:             "secret",
			projectID:          "project1",
			provideAuthToken:   true,
			expectedCode:       200,
			provideString:      false,
			provideOrgIDString: false,
		},
		{
			description:        "failed authorization",
			secret:             "secret",
			projectID:          "project1",
			provideAuthToken:   false,
			expectedCode:       401,
			provideString:      false,
			provideOrgIDString: false,
		},
		{
			description:        "provide string as ID",
			secret:             "secret",
			projectID:          "project1",
			provideAuthToken:   true,
			expectedCode:       422,
			provideString:      true,
			provideOrgIDString: false,
		},
		{
			description:        "provide orgID as string",
			secret:             "secret",
			projectID:          "project1",
			provideAuthToken:   true,
			expectedCode:       422,
			provideString:      true,
			provideOrgIDString: true,
		},
	}

	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		OrgID := 1
		// create httpRequest object
		request, _ := http.NewRequest("DELETE", fmt.Sprintf("/v1/admin/organizations/%d/users/%d", OrgID, ID), nil)
		if testCase.provideString {
			request, _ = http.NewRequest("DELETE", fmt.Sprintf("/v1/admin/organizations/%d/users/%s", OrgID, "ID"), nil)
		}
		if testCase.provideOrgIDString {
			request, _ = http.NewRequest("DELETE", fmt.Sprintf("/v1/admin/organizations/%s/users/%d", "OrgID", ID), nil)
		}
		response := httptest.NewRecorder()
		if testCase.provideAuthToken {
			testHelper.SetRequestAuthHeader(testCase.secret, testCase.projectID,
				request)
			if !testCase.provideString {
				mockedHandle.EXPECT().GetUserID(clientContainer, ID)
				mockedHandle.EXPECT().GetOrganizationID(clientContainer, OrgID)
				mockedHandle.EXPECT().DeleteOrganizationUser(clientContainer, ID, OrgID)
			}
		}
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			testCase.secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
	}
}

func TestGrafanaUserGet(t *testing.T) {
	testCases := []struct {
		description    string
		expectedResult []grafanaclient.User
		output         []byte
	}{
		{
			description:    "Response Check",
			expectedResult: []grafanaclient.User{grafanaclient.User{ID: 1, Name: "", Login: "admin", Email: "admin@localhost"}},
			output:         []byte(`[{"userID":"1","name":"","login":"admin","email":"admin@localhost"}]`),
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)
		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().GetUsers().Return(testCase.expectedResult, nil)
		handler := v1Api.V1Handler{}
		result, err := handler.GetUsers(clientContainer)
		assert.Equal(t, result, testCase.output, "response match")
		assert.Equal(t, nil, err, "no error")

	}
}

func TestGrafanaUserGetID(t *testing.T) {
	testCases := []struct {
		description    string
		expectedResult grafanaclient.User
		output         []byte
	}{
		{
			description:    "Response Check",
			expectedResult: grafanaclient.User{ID: 1, Name: "", Login: "admin", Email: "admin@localhost", OrgID: 1},
			output:         []byte(`{"userID":"1","name":"","login":"admin","email":"admin@localhost","orgID":"1"}`),
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)
		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().GetUserID(ID).Return(
			testCase.expectedResult, nil)
		handler := v1Api.V1Handler{}
		result, err := handler.GetUserID(clientContainer, ID)
		assert.Equal(t, testCase.output, result, "response match")
		assert.Equal(t, nil, err, "no error")

	}
}

func TestGrafanaUserCreate(t *testing.T) {
	testCases := []struct {
		description string
		input       grafanaclient.AdminCreateUser
		params      []byte
	}{
		{
			description: "Response Check",
			input:       grafanaclient.AdminCreateUser{Name: "admin", Login: "admin", Email: "admin@localhost.com", Password: "password"},
			params:      []byte(`{"Name":"admin","Email":"admin@localhost.com","Login":"admin","Password":"password"}`),
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)

		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().CreateUser(testCase.input)
		handler := v1Api.V1Handler{}
		err := handler.CreateUser(clientContainer, testCase.params)
		assert.Equal(t, nil, err, "no error")

	}
}

func TestGrafanaUserDelete(t *testing.T) {
	testCases := []struct {
		description    string
		expectedResult error
	}{
		{
			description:    "Response Check",
			expectedResult: nil,
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)
		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().DeleteUser(ID).Return(nil)
		handler := v1Api.V1Handler{}
		err := handler.DeleteUser(clientContainer, ID)
		assert.Equal(t, testCase.expectedResult, err, "no error")

	}
}

func TestGrafanaOrganizationGet(t *testing.T) {
	testCases := []struct {
		description    string
		expectedResult []grafanaclient.OrgList
		output         []byte
	}{
		{
			description:    "Response Check",
			expectedResult: []grafanaclient.OrgList{grafanaclient.OrgList{ID: 1, Name: "Main Org."}},
			output:         []byte(`[{"name":"Main Org.","organizationID":"1"}]`),
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)
		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().GetOrganizations().Return(
			testCase.expectedResult, nil)
		handler := v1Api.V1Handler{}
		result, err := handler.GetOrganizations(clientContainer)
		assert.Equal(t, result, testCase.output, "response match")
		assert.Equal(t, nil, err, "no error")

	}
}

func TestGrafanaOrganizationGetID(t *testing.T) {
	testCases := []struct {
		description    string
		expectedResult grafanaclient.OrgList
		output         []byte
	}{
		{
			description:    "Response Check",
			expectedResult: grafanaclient.OrgList{ID: 1, Name: "Main Org."},
			output:         []byte(`{"organizationID":"1","name":"Main Org."}`),
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)
		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().GetOrganizationID(ID).Return(
			testCase.expectedResult, nil)
		handler := v1Api.V1Handler{}
		result, err := handler.GetOrganizationID(clientContainer, ID)
		assert.Equal(t, result, testCase.output, "response match")
		assert.Equal(t, nil, err, "no error")

	}
}

func TestGrafanaOrganizationCreate(t *testing.T) {
	testCases := []struct {
		description string
		input       grafanaclient.Org
		params      []byte
	}{
		{
			description: "Response Check",
			input:       grafanaclient.Org{Name: "org1"},
			params:      []byte(`{"Name":"org1"}`),
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)

		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().CreateOrganization(testCase.input)
		handler := v1Api.V1Handler{}
		err := handler.CreateOrganization(clientContainer, testCase.params)
		assert.Equal(t, nil, err, "no error")

	}
}

func TestGrafanaOrgDelete(t *testing.T) {
	testCases := []struct {
		description    string
		expectedResult error
	}{
		{
			description:    "Response Check",
			expectedResult: nil,
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)
		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().DeleteOrganization(ID).Return(nil)
		handler := v1Api.V1Handler{}
		err := handler.DeleteOrganization(clientContainer, ID)
		assert.Equal(t, testCase.expectedResult, err, "no error")

	}
}

func TestGrafanaOrgUserGet(t *testing.T) {
	testCases := []struct {
		description    string
		expectedResult []grafanaclient.OrgUserList
		output         []byte
	}{
		{
			description:    "Response Check",
			expectedResult: []grafanaclient.OrgUserList{grafanaclient.OrgUserList{OrgID: 1, UserID: 1, Login: "admin", Role: "Viewer"}},
			output:         []byte(`[{"organizationID":"1","userID":"1","login":"admin","role":"Viewer","email":""}]`),
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)
		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().GetOrganizationUsers(ID).Return(
			testCase.expectedResult, nil)
		handler := v1Api.V1Handler{}
		result, err := handler.GetOrganizationUsers(clientContainer, ID)
		assert.Equal(t, result, testCase.output, "response match")
		assert.Equal(t, nil, err, "no error")

	}
}

func TestGrafanaOrgUserCreate(t *testing.T) {
	testCases := []struct {
		description string
		input       grafanaclient.CreateOrganizationUser
		params      []byte
	}{
		{
			description: "Response Check",
			input:       grafanaclient.CreateOrganizationUser{Name: "admin", Login: "admin", Email: "admin@localhost.com", Password: "password", Role: "Viewer"},
			params:      []byte(`{"Name": "admin", "Login": "admin", "Email": "admin@localhost.com", "Password": "password", "Role": "Viewer"}`),
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)

		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().CreateOrganizationUser(ID, testCase.input)
		handler := v1Api.V1Handler{}
		err := handler.CreateOrganizationUser(clientContainer, ID, testCase.params)
		assert.Equal(t, nil, err, "no error")

	}
}

func TestGrafanaOrgUserDelete(t *testing.T) {
	testCases := []struct {
		description    string
		expectedResult error
	}{
		{
			description:    "Response Check",
			expectedResult: nil,
		},
	}
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		OrgID := 1
		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)
		mockedGrafana.EXPECT().DoLogon()
		mockedGrafana.EXPECT().DeleteOrganizationUser(ID, OrgID).Return(nil)
		handler := v1Api.V1Handler{}
		err := handler.DeleteOrganizationUser(clientContainer, ID, OrgID)
		assert.Equal(t, testCase.expectedResult, err, "no error")

	}
}
