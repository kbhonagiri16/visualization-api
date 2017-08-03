package v1Apitest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"visualization-api/pkg/database/mock"
	"visualization-api/pkg/database/models"
	"visualization-api/pkg/grafanaclient/mock"
	"visualization-api/pkg/http_endpoint"
	"visualization-api/pkg/http_endpoint/common"
	"visualization-api/pkg/http_endpoint/common/mock"
	"visualization-api/pkg/http_endpoint/common/tests"
	"visualization-api/pkg/http_endpoint/v1/handlers"
)

func TestVisualizationsGetTagsAndName(t *testing.T) {

	testCases := []struct {
		description string
		query       string
		name        string
		tags        map[string]interface{}
	}{
		{
			description: "both name and tags are provided",
			query:       "?name=name&tag1=tag1&tag2=tag2",
			name:        "name",
			tags:        map[string]interface{}{"tag1": "tag1", "tag2": "tag2"},
		},
		{
			description: "both name and tags are not provided",
			query:       "",
			name:        "",
			tags:        map[string]interface{}{},
		},
		{
			description: "only tags are provided",
			query:       "?tag1=tag1&tag2=tag2",
			name:        "",
			tags:        map[string]interface{}{"tag1": "tag1", "tag2": "tag2"},
		},
		{
			description: "only name is provided",
			query:       "?name=name",
			name:        "name",
			tags:        map[string]interface{}{},
		},
	}

	const projectID = "3"
	const secret = "secret"

	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		request, _ := http.NewRequest("GET", "/v1/visualizations"+testCase.query, nil)
		testHelper.SetRequestAuthHeader(secret, projectID, request)
		mockedHandle.EXPECT().VisualizationsGet(clientContainer, projectID,
			testCase.name, testCase.tags)
		response := httptest.NewRecorder()
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			secret).ServeHTTP(response, request)
	}
}

func TestVisualizationsGetResponses(t *testing.T) {

	testCases := []struct {
		description          string
		tokenProvided        bool
		expectedCode         int
		expectedResult       string
		handlerErrorExpected bool
		handlerResult        *[]common.VisualizationWithDashboards
	}{
		{
			description:          "check 401 on auth token missing",
			tokenProvided:        false,
			expectedCode:         401,
			handlerErrorExpected: false,
			handlerResult:        nil,
		},
		{
			description:          "check 500 handler error",
			tokenProvided:        true,
			expectedCode:         500,
			handlerErrorExpected: true,
			handlerResult:        nil,
		},
		{
			description:          "check 200 in positive outcome",
			tokenProvided:        true,
			expectedCode:         200,
			handlerErrorExpected: false,
			expectedResult:       "[{\"id\":\"visualization_id\",\"name\":\"visualization_name\",\"tags\":\"{\\\"tag1\\\": \\\"tag1\\\"}\",\"dashboards\":[{\"name\":\"dashboard_name\",\"renderedTemplate\":\"dashboard_template\",\"id\":\"dashboard_slug\"}]}]",
			handlerResult: &[]common.VisualizationWithDashboards{
				common.VisualizationWithDashboards{
					&common.VisualizationResponseEntry{
						"visualization_id",
						"visualization_name",
						"{\"tag1\": \"tag1\"}"},
					[]*common.DashboardResponseEntry{
						&common.DashboardResponseEntry{
							"dashboard_name",
							"dashboard_template",
							"dashboard_slug"},
					},
				},
			},
		},
	}

	const projectID = "3"
	const secret = "secret"

	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		request, _ := http.NewRequest("GET", "/v1/visualizations", nil)
		if testCase.tokenProvided {
			testHelper.SetRequestAuthHeader(secret, projectID, request)
			if testCase.handlerErrorExpected {
				mockedHandle.EXPECT().VisualizationsGet(clientContainer, projectID,
					"", map[string]interface{}{}).Return(testCase.handlerResult, errors.New(""))
			} else {
				mockedHandle.EXPECT().VisualizationsGet(clientContainer, projectID,
					"", map[string]interface{}{}).Return(testCase.handlerResult, nil)
			}
		}
		response := httptest.NewRecorder()
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
		if !testCase.handlerErrorExpected && testCase.tokenProvided {
			responseData, _ := ioutil.ReadAll(response.Body)
			assert.Equal(t, testCase.expectedResult, string(responseData),
				"response body match")
		}
	}
}

func TestVisualizationDeleteUUIDArg(t *testing.T) {

	testCases := []struct {
		description          string
		visualizationID      string
		visualizationIDValid bool
		expectedCode         int
	}{
		{
			description:          "provided id is not valid",
			visualizationID:      "not_uuid",
			visualizationIDValid: false,
			expectedCode:         422,
		},
		{
			description:          "provided id is valid",
			visualizationID:      "0f29d63b-be6f-43cf-b99f-23271b3e6041",
			visualizationIDValid: true,
			expectedCode:         200,
		},
	}

	const projectID = "3"
	const secret = "secret"

	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		url := fmt.Sprintf("/v1/visualization/%s", testCase.visualizationID)
		request, _ := http.NewRequest("DELETE", url, nil)
		testHelper.SetRequestAuthHeader(secret, projectID, request)
		if testCase.visualizationIDValid {
			mockedHandle.EXPECT().VisualizationDelete(clientContainer, projectID, testCase.visualizationID)
		}
		response := httptest.NewRecorder()
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
	}
}

func TestVisualizationDeleteResponses(t *testing.T) {
	testCases := []struct {
		description          string
		tokenProvided        bool
		visualizationID      string
		expectedCode         int
		expectedResult       string
		handlerErrorExpected bool
		returnedError        error
		handlerResult        *common.VisualizationWithDashboards
	}{
		{
			description:          "check 401 on auth token missing",
			tokenProvided:        false,
			expectedCode:         401,
			handlerErrorExpected: false,
			handlerResult:        nil,
			returnedError:        nil,
			visualizationID:      "0f29d63b-be6f-43cf-b99f-23271b3e6041",
		},
		{
			description:          "check 404 on auth token missing",
			tokenProvided:        true,
			expectedCode:         404,
			handlerErrorExpected: true,
			returnedError:        common.NewUserDataError("test"),
			handlerResult:        nil,
			visualizationID:      "0f29d63b-be6f-43cf-b99f-23271b3e6041",
			expectedResult:       "{\"code\":404,\"message\":\"Not Found\",\"details\":\"Requested visualization '0f29d63b-be6f-43cf-b99f-23271b3e6041' was not found\"}",
		},
		{
			description:          "check 500 handler with returned outcome",
			tokenProvided:        true,
			expectedCode:         500,
			handlerErrorExpected: true,
			returnedError:        common.NewClientError("test"),
			expectedResult:       "{\"id\":\"visualization_id\",\"name\":\"visualization_name\",\"tags\":\"{\\\"tag1\\\": \\\"tag1\\\"}\",\"dashboards\":[{\"name\":\"dashboard_name\",\"renderedTemplate\":\"dashboard_template\",\"id\":\"dashboard_slug\"}]}",
			visualizationID:      "0f29d63b-be6f-43cf-b99f-23271b3e6041",
			handlerResult: &common.VisualizationWithDashboards{
				&common.VisualizationResponseEntry{
					"visualization_id",
					"visualization_name",
					"{\"tag1\": \"tag1\"}"},
				[]*common.DashboardResponseEntry{
					&common.DashboardResponseEntry{
						"dashboard_name",
						"dashboard_template",
						"dashboard_slug"},
				},
			},
		},
		{
			description:          "check 500 handler error",
			tokenProvided:        true,
			expectedCode:         500,
			handlerErrorExpected: true,
			returnedError:        errors.New("test"),
			handlerResult:        nil,
			visualizationID:      "0f29d63b-be6f-43cf-b99f-23271b3e6041",
			expectedResult:       "{\"code\":500,\"message\":\"Internal Server Error\",\"details\":\"Internal server error occured\"}",
		},
		{
			description:          "check 200 in positive outcome",
			tokenProvided:        true,
			visualizationID:      "0f29d63b-be6f-43cf-b99f-23271b3e6041",
			expectedCode:         200,
			handlerErrorExpected: false,
			expectedResult:       "{\"id\":\"visualization_id\",\"name\":\"visualization_name\",\"tags\":\"{\\\"tag1\\\": \\\"tag1\\\"}\",\"dashboards\":[{\"name\":\"dashboard_name\",\"renderedTemplate\":\"dashboard_template\",\"id\":\"dashboard_slug\"}]}",
			handlerResult: &common.VisualizationWithDashboards{
				&common.VisualizationResponseEntry{
					"visualization_id",
					"visualization_name",
					"{\"tag1\": \"tag1\"}"},
				[]*common.DashboardResponseEntry{
					&common.DashboardResponseEntry{
						"dashboard_name",
						"dashboard_template",
						"dashboard_slug"},
				},
			},
		},
	}

	const projectID = "3"
	const secret = "secret"

	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		request, _ := http.NewRequest("DELETE",
			fmt.Sprintf("/v1/visualization/%s", testCase.visualizationID), nil)
		if testCase.tokenProvided {
			testHelper.SetRequestAuthHeader(secret, projectID, request)
			if testCase.handlerErrorExpected {
				mockedHandle.EXPECT().VisualizationDelete(clientContainer, projectID,
					testCase.visualizationID).Return(testCase.handlerResult, testCase.returnedError)
			} else {
				mockedHandle.EXPECT().VisualizationDelete(clientContainer, projectID,
					testCase.visualizationID).Return(testCase.handlerResult, nil)
			}
		}
		response := httptest.NewRecorder()
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
		if testCase.tokenProvided {
			responseData, _ := ioutil.ReadAll(response.Body)
			assert.Equal(t, testCase.expectedResult, string(responseData),
				"response body match")
		}
	}
}

func TestVisualizationPostResponses(t *testing.T) {
	testCases := []struct {
		description          string
		tokenProvided        bool
		payloadProvided      string
		payloadValid         bool
		expectedCode         int
		expectedResult       string
		handlerErrorExpected bool
		returnedError        error
		handlerResult        *common.VisualizationWithDashboards
	}{
		{
			description:          "check 401 on auth token missing",
			tokenProvided:        false,
			expectedCode:         401,
			handlerErrorExpected: false,
			handlerResult:        nil,
			returnedError:        nil,
		},
		{
			description:          "check 200 on positive outcome",
			payloadProvided:      "{\"name\": \"test_name\", \"tags\": {\"tag1\": \"tag_value1\"}, \"dashboards\": [{\"name\": \"dashboard_name\", \"templateBody\": \"template\", \"templateParameters\": {\"param1\": \"value1\"}}]}",
			payloadValid:         true,
			tokenProvided:        true,
			expectedCode:         200,
			handlerErrorExpected: false,
			returnedError:        nil,
			expectedResult:       "{\"id\":\"visualization_id\",\"name\":\"visualization_name\",\"tags\":\"{\\\"tag1\\\": \\\"tag1\\\"}\",\"dashboards\":[{\"name\":\"dashboard_name\",\"renderedTemplate\":\"dashboard_template\",\"id\":\"dashboard_slug\"}]}",
			handlerResult: &common.VisualizationWithDashboards{
				&common.VisualizationResponseEntry{
					"visualization_id",
					"visualization_name",
					"{\"tag1\": \"tag1\"}"},
				[]*common.DashboardResponseEntry{
					&common.DashboardResponseEntry{
						"dashboard_name",
						"dashboard_template",
						"dashboard_slug"},
				},
			},
		},
		{
			description:          "check 422 on mailformed json",
			payloadProvided:      "{\"name\": \"test_name\", \"tags\": {\"tag1\": \"tag_value1\"}, \"dashboards\": [{\"name\": \"dashboard_name\", \"templateBody\": \"template\", \"templateParameters\": {\"param1\": \"value1\"}}]",
			payloadValid:         false,
			tokenProvided:        true,
			expectedCode:         422,
			handlerErrorExpected: false,
			expectedResult:       "{\"code\":422,\"message\":\"Unprocessable Entity\",\"details\":\"Error parsing json body 'unexpected EOF'\"}",
		},
		{
			description:          "check 422 on invalid json schema",
			payloadProvided:      "{\"tags\": {\"tag1\": \"tag_value1\"}, \"dashboards\": [{\"name\": \"dashboard_name\", \"templateBody\": \"template\", \"templateParameters\": {\"param1\": \"value1\"}}]}",
			payloadValid:         false,
			tokenProvided:        true,
			expectedCode:         422,
			handlerErrorExpected: false,
			expectedResult:       "{\"code\":422,\"message\":\"Unprocessable Entity\",\"details\":\"request body is not valid, list of erros [name: name is required]\"}",
		},
		{
			description:          "check 422 on invalid json schema",
			payloadProvided:      "{\"name\": \"test_name\", \"tags\": {\"tag1\": \"tag_value1\"}}]}",
			payloadValid:         false,
			tokenProvided:        true,
			expectedCode:         422,
			handlerErrorExpected: false,
			expectedResult:       "{\"code\":422,\"message\":\"Unprocessable Entity\",\"details\":\"request body is not valid, list of erros [dashboards: dashboards is required]\"}",
		},
		{
			description:          "check 422 on mailformed json",
			payloadProvided:      "{\"name\": \"test_name\", \"tags\": {\"tag1\": \"tag_value1\"}, \"dashboards\": [{\"templateBody\": \"template\", \"templateParameters\": {\"param1\": \"value1\"}}]}",
			payloadValid:         false,
			tokenProvided:        true,
			expectedCode:         422,
			handlerErrorExpected: false,
			expectedResult:       "{\"code\":422,\"message\":\"Unprocessable Entity\",\"details\":\"request body is not valid, list of erros [name: name is required]\"}",
		},
		{
			description:          "check 422 on mailformed json",
			payloadProvided:      "{\"name\": \"test_name\", \"tags\": {\"tag1\": \"tag_value1\"}, \"dashboards\": [{\"name\": \"dashboard_name\", \"templateParameters\": {\"param1\": \"value1\"}}]}",
			payloadValid:         false,
			tokenProvided:        true,
			expectedCode:         422,
			handlerErrorExpected: false,
			expectedResult:       "{\"code\":422,\"message\":\"Unprocessable Entity\",\"details\":\"request body is not valid, list of erros [dashboards.0: Must validate one and only one schema (oneOf)templateBody: templateBody is requireddashboards.0: Must validate all the schemas (allOf)]\"}",
		},
		{
			description:          "check 422 on mailformed json",
			payloadProvided:      "{\"name\": \"test_name\", \"tags\": {\"tag1\": \"tag_value1\"}, \"dashboards\": [{\"name\": \"dashboard_name\", \"templateBody\": \"template\"}]}",
			payloadValid:         false,
			tokenProvided:        true,
			expectedCode:         422,
			handlerErrorExpected: false,
			expectedResult:       "{\"code\":422,\"message\":\"Unprocessable Entity\",\"details\":\"request body is not valid, list of erros [templateParameters: templateParameters is required]\"}",
		},
		{
			description:          "check 500 with returned data",
			payloadProvided:      "{\"name\": \"test_name\", \"tags\": {\"tag1\": \"tag_value1\"}, \"dashboards\": [{\"name\": \"dashboard_name\", \"templateBody\": \"template\", \"templateParameters\": {\"param1\": \"value1\"}}]}",
			payloadValid:         true,
			tokenProvided:        true,
			expectedCode:         500,
			handlerErrorExpected: true,
			returnedError:        common.NewClientError("test"),
			expectedResult:       "{\"id\":\"visualization_id\",\"name\":\"visualization_name\",\"tags\":\"{\\\"tag1\\\": \\\"tag1\\\"}\",\"dashboards\":[{\"name\":\"dashboard_name\",\"renderedTemplate\":\"dashboard_template\",\"id\":\"dashboard_slug\"}]}",
			handlerResult: &common.VisualizationWithDashboards{
				&common.VisualizationResponseEntry{
					"visualization_id",
					"visualization_name",
					"{\"tag1\": \"tag1\"}"},
				[]*common.DashboardResponseEntry{
					&common.DashboardResponseEntry{
						"dashboard_name",
						"dashboard_template",
						"dashboard_slug"},
				},
			},
		},
		{
			description:          "check 422 template error",
			payloadProvided:      "{\"name\": \"test_name\", \"tags\": {\"tag1\": \"tag_value1\"}, \"dashboards\": [{\"name\": \"dashboard_name\", \"templateBody\": \"template\", \"templateParameters\": {\"param1\": \"value1\"}}]}",
			payloadValid:         true,
			tokenProvided:        true,
			expectedCode:         422,
			handlerErrorExpected: true,
			returnedError:        common.NewUserDataError("test"),
			expectedResult:       "{\"code\":422,\"message\":\"Unprocessable Entity\",\"details\":\"Error rendering template 'test'\"}",
		},
		{
			description:          "check 500",
			payloadProvided:      "{\"name\": \"test_name\", \"tags\": {\"tag1\": \"tag_value1\"}, \"dashboards\": [{\"name\": \"dashboard_name\", \"templateBody\": \"template\", \"templateParameters\": {\"param1\": \"value1\"}}]}",
			payloadValid:         true,
			tokenProvided:        true,
			expectedCode:         500,
			handlerErrorExpected: true,
			returnedError:        errors.New("test"),
			expectedResult:       "{\"code\":500,\"message\":\"Internal Server Error\",\"details\":\"Internal server error occured\"}",
		},
	}

	const projectID = "3"
	const secret = "secret"

	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		mockedHandle := mock_common.NewMockHandlerInterface(mockCtrl)
		clientContainer := testHelper.MockClientContainer(mockCtrl)

		jsonStr := []byte(testCase.payloadProvided)
		request, _ := http.NewRequest("POST", "/v1/visualizations", bytes.NewBuffer(jsonStr))
		request.Header.Set("Content-Type", "application/json")
		if testCase.tokenProvided {
			testHelper.SetRequestAuthHeader(secret, projectID, request)
		}
		if testCase.payloadValid {
			payload := common.VisualizationPOSTData{}
			json.Unmarshal([]byte(testCase.payloadProvided), &payload)
			if testCase.handlerErrorExpected {
				mockedHandle.EXPECT().VisualizationsPost(clientContainer, payload, projectID).Return(testCase.handlerResult, testCase.returnedError)
			} else {
				mockedHandle.EXPECT().VisualizationsPost(clientContainer, payload, projectID).Return(testCase.handlerResult, nil)
			}
		}
		response := httptest.NewRecorder()
		endpoint.InitializeRouter(clientContainer, mockedHandle,
			secret).ServeHTTP(response, request)
		assert.Equal(t, testCase.expectedCode, response.Code,
			"response code match")
		if testCase.tokenProvided {
			responseData, _ := ioutil.ReadAll(response.Body)
			assert.Equal(t, testCase.expectedResult, string(responseData),
				"response body match")
		}
	}
}

func TestVisualizationDashboardToResponse(t *testing.T) {
	testCases := []struct {
		visualization *models.Visualization
		dashboards    []*models.Dashboard
		result        *common.VisualizationWithDashboards
	}{
		{
			visualization: &models.Visualization{1, "visualization_slug", "visualization_name", "organization_id", "visualization_tags"},
			dashboards: []*models.Dashboard{
				&models.Dashboard{"id", 1, "dashboard_name", "rendered_template", "dashboard_slug"},
			},
			result: &common.VisualizationWithDashboards{
				&common.VisualizationResponseEntry{"visualization_slug", "visualization_name", "visualization_tags"},
				[]*common.DashboardResponseEntry{
					&common.DashboardResponseEntry{"dashboard_name", "rendered_template", "dashboard_slug"},
				},
			},
		},
	}

	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		returnedResult := v1handlers.VisualizationDashboardToResponse(testCase.visualization, testCase.dashboards)
		assert.Equal(t, testCase.result, returnedResult,
			"result must match")
	}
}

func TestGroupedVisualizationDashboardToResponse(t *testing.T) {
	testCases := []struct {
		inputDataMap *map[models.Visualization][]*models.Dashboard
		result       *[]common.VisualizationWithDashboards
	}{
		{
			inputDataMap: &map[models.Visualization][]*models.Dashboard{
				models.Visualization{1, "visualization_slug", "visualization_name", "organization_id", "visualization_tags"}: []*models.Dashboard{
					&models.Dashboard{"id", 1, "dashboard_name", "rendered_template", "dashboard_slug"}},
			},
			result: &[]common.VisualizationWithDashboards{
				common.VisualizationWithDashboards{
					&common.VisualizationResponseEntry{"visualization_slug", "visualization_name", "visualization_tags"},
					[]*common.DashboardResponseEntry{
						&common.DashboardResponseEntry{"dashboard_name", "rendered_template", "dashboard_slug"},
					},
				},
			},
		},
	}

	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		returnedResult := v1handlers.GroupedVisualizationDashboardToResponse(testCase.inputDataMap)
		assert.Equal(t, testCase.result, returnedResult,
			"result must match")
	}
}

func TestVisualizationsGetHandler(t *testing.T) {
	testCases := []struct {
		dbData        *map[models.Visualization][]*models.Dashboard
		result        *[]common.VisualizationWithDashboards
		name          string
		tags          map[string]interface{}
		expectDBError bool
	}{
		{
			dbData: &map[models.Visualization][]*models.Dashboard{
				models.Visualization{1, "visualization_slug", "visualization_name", "organization_id", "visualization_tags"}: []*models.Dashboard{
					&models.Dashboard{"id", 1, "dashboard_name", "rendered_template", "dashboard_slug"}},
			},
			result: &[]common.VisualizationWithDashboards{
				common.VisualizationWithDashboards{
					&common.VisualizationResponseEntry{"visualization_slug", "visualization_name", "visualization_tags"},
					[]*common.DashboardResponseEntry{
						&common.DashboardResponseEntry{"dashboard_name", "rendered_template", "dashboard_slug"},
					},
				},
			},
			name:          "name",
			expectDBError: false,
		},
		{
			dbData: &map[models.Visualization][]*models.Dashboard{
				models.Visualization{1, "visualization_slug", "visualization_name", "organization_id", "visualization_tags"}: []*models.Dashboard{
					&models.Dashboard{"id", 1, "dashboard_name", "rendered_template", "dashboard_slug"}},
			},
			result: &[]common.VisualizationWithDashboards{
				common.VisualizationWithDashboards{
					&common.VisualizationResponseEntry{"visualization_slug", "visualization_name", "visualization_tags"},
					[]*common.DashboardResponseEntry{
						&common.DashboardResponseEntry{"dashboard_name", "rendered_template", "dashboard_slug"},
					},
				},
			},
			name:          "name",
			expectDBError: true,
		},
	}

	const projectID = "3"
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedDatabaseManager := clientContainer.DatabaseManager.(*mock_database.MockDatabaseManager)
		if testCase.expectDBError {
			mockedDatabaseManager.EXPECT().QueryVisualizationsDashboards("", testCase.name, projectID, testCase.tags).Return(nil, errors.New("test"))
		} else {
			mockedDatabaseManager.EXPECT().QueryVisualizationsDashboards("", testCase.name, projectID, testCase.tags).Return(testCase.dbData, nil)
		}
		handler := v1handlers.V1Visualizations{}
		visualizationsData, returnedError := handler.VisualizationsGet(clientContainer,
			projectID, testCase.name, testCase.tags)
		if testCase.expectDBError {
			assert.NotNil(t, returnedError)
		} else {
			assert.Equal(t, testCase.result, visualizationsData,
				"result must match")
		}
	}
}

func TestVisualizationsDeleteHandler(t *testing.T) {
	testCases := []struct {
		databaseVisualization *models.Visualization
		databaseDashboards    []*models.Dashboard
		result                *common.VisualizationWithDashboards
		visualizationSlug     string
		slugFoundInDB         bool
	}{
		{
			databaseVisualization: &models.Visualization{1, "visualization_slug", "visualization_name", "organization_id", "visualization_tags"},
			databaseDashboards: []*models.Dashboard{
				&models.Dashboard{"id", 1, "dashboard_name", "rendered_template", "dashboard_slug"},
			},
			result: &common.VisualizationWithDashboards{
				&common.VisualizationResponseEntry{"visualization_slug", "visualization_name", "visualization_tags"},
				[]*common.DashboardResponseEntry{
					&common.DashboardResponseEntry{"dashboard_name", "rendered_template", "dashboard_slug"},
				},
			},
			visualizationSlug: "slug",
			slugFoundInDB:     true,
		},
		{
			visualizationSlug: "slug",
			slugFoundInDB:     false,
		},
	}

	const projectID = "3"
	testHelper.InitializeLogger()
	for _, testCase := range testCases {
		mockCtrl := gomock.NewController(t)
		defer mockCtrl.Finish()
		clientContainer := testHelper.MockClientContainer(mockCtrl)
		mockedDatabaseManager := clientContainer.DatabaseManager.(*mock_database.MockDatabaseManager)
		mockedGrafana := clientContainer.Grafana.(*mock_grafanaclient.MockSessionInterface)
		mockedDatabaseManager.EXPECT().GetVisualizationWithDashboardsBySlug(testCase.visualizationSlug, projectID).Return(testCase.databaseVisualization, testCase.databaseDashboards, nil)

		if testCase.slugFoundInDB {
			for _, dashboard := range testCase.databaseDashboards {
				mockedGrafana.EXPECT().DeleteDashboard(dashboard.Slug, projectID)
			}
			mockedDatabaseManager.EXPECT().DeleteVisualization(testCase.databaseVisualization)
		}

		handler := v1handlers.V1Visualizations{}
		visualizationsData, returnedError := handler.VisualizationDelete(clientContainer,
			projectID, testCase.visualizationSlug)
		assert.Equal(t, testCase.result, visualizationsData,
			"result must match")

		if !testCase.slugFoundInDB {
			assert.NotNil(t, returnedError)
		}
	}
}
