package v1Apitest

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"visualization-api/pkg/grafanaclient"
	"visualization-api/pkg/grafanaclient/mock"
	"visualization-api/pkg/http_endpoint"
	"visualization-api/pkg/http_endpoint/common"
	"visualization-api/pkg/http_endpoint/common/mock"
	"visualization-api/pkg/http_endpoint/common/tests"
	"visualization-api/pkg/http_endpoint/v1"
	"visualization-api/pkg/openstack"
	"visualization-api/pkg/openstack/mock"
)

const openstackTokenHeaderName = "X-OpenStack-Auth-Token"
const authSecret = "secret"

func TestAuthEndpoint(t *testing.T) {

	testCases := []struct {
		description      string
		authToken        string
		provideAuthToken bool
		expectedCode     int
		expectedData     string
	}{
		{
			description:      "not provide authToken",
			authToken:        "",
			provideAuthToken: false,
			expectedCode:     401,
			expectedData:     "{\"code\":401,\"message\":\"Unauthorized. Token is invalid or expired.\",\"details\":\"header X-OpenStack-Auth-Token is not specified\"}",
		},
		{
			description:      "provide authToken",
			authToken:        "token",
			provideAuthToken: true,
			expectedCode:     200,
			expectedData:     "token",
		},
	}

	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		request, _ := http.NewRequest("POST", "/v1/auth/openstack", nil)
		if testCase.provideAuthToken {
			request.Header.Set(openstackTokenHeaderName, testCase.authToken)
			mockedHandle.EXPECT().AuthOpenstack(clientContainer,
				&common.RealClock{}, testCase.authToken,
				authSecret).Return([]byte(testCase.authToken), nil)
		}

		response := httptest.NewRecorder()
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			authSecret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
		responseData, _ := ioutil.ReadAll(response.Body)
		assert.Equal(t, testCase.expectedData, string(responseData),
			"response body match")
	}
}

func TestAuthHandler(t *testing.T) {
	parsedTime, _ := time.Parse(time.RFC3339, "2017-06-15T00:48:41Z")
	testCases := []struct {
		description    string
		token          string
		secret         string
		tokenValid     bool
		tokenInfo      *openstack.TokenInfo
		expectedResult []byte
		returnID       int
	}{
		{
			description: "t",
			token:       "token",
			secret:      "secret",
			tokenValid:  false,
		},
		{
			description: "t",
			token:       "token",
			secret:      "secret",
			tokenValid:  true,
			tokenInfo: &openstack.TokenInfo{
				ID:          "ID",
				ProjectName: "test",
				ProjectID:   "821fb77b2ab94232a1ff3d40028f63b4",
				ExpiresAt:   parsedTime,
			},
			returnID:       3,
			expectedResult: []byte(`{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc0FkbWluIjpmYWxzZSwib3JnSWQiOiIzIiwiZXhwIjoxNDk3NDg3NzIxfQ.gxv4nFfuvhtZ6Q2Q5ii6J29s1oTcUXcQOLk08JWlAZU","token":{"organizationId":"3","expiresAt":"2017-06-15T00:48:41Z","isAdmin":false}}`),
		},
	}

	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()

		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedOpenstack := clientContainer.Openstack.(*mock_openstack.MockClientInterface)
		mockedOpenstack.EXPECT().ValidateToken(testCase.token).Return(
			testCase.tokenValid, nil)
		mockedClock := mock_common.NewMockClockInterface(mockCtrl)
		if testCase.tokenValid {
			mockedOpenstack.EXPECT().GetTokenInfo(testCase.token).Return(
				testCase.tokenInfo, nil)
			orgID := &grafanaclient.OrgID{}
			orgID.ID = testCase.returnID
			clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface).EXPECT().GetOrCreateOrgByName(testCase.tokenInfo.ProjectName+"-"+testCase.tokenInfo.ProjectID).Return(orgID, nil)
			mockedClock.EXPECT().Now().Return(parsedTime.Add(
				-v1Api.TokenIssueHours * time.Hour))
		}
		handler := v1Api.V1Handler{}
		authResult, err := handler.AuthOpenstack(clientContainer, mockedClock,
			testCase.token, testCase.secret)

		if testCase.tokenValid {
			assert.Equal(t, testCase.expectedResult, authResult, "AuthResult check failed")
		} else {
			assert.Equal(t, common.InvalidOpenstackToken{}, err,
				"Required Error was not returned")
		}
	}
}
