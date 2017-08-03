package v1handlers

import (
	"encoding/json"
	"fmt"
	"github.com/ponzu-cms/ponzu/cmd/ponzu/vendor/github.com/satori/go.uuid"
	"github.com/pressly/chi"
	//"github.com/satori/go.uuid"
	"github.com/xeipuuv/gojsonschema"
	"io/ioutil"
	"net/http"
	"visualization-api/pkg/http_endpoint/common"
	v1JsonSchema "visualization-api/pkg/http_endpoint/v1/json_schemas"
	"visualization-api/pkg/logging"
)

const visualizationNameParam = "name"

// VisualizationsGet returns http handler with stored clients and handler pointers
func VisualizationsGet(clients *common.ClientContainer,
	handler common.HandlerInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// This function is triggered by router. We have to parse / validate
		// all data from http request and call handle function

		organizationID := r.Context().Value(common.OrganizationIDContext).(string)

		var name string
		tags := make(map[string]interface{})

		providedArgs := r.URL.Query()
		for paramName, paramValue := range providedArgs {
			// only one tag value currently allowed for one tag name
			tagValue := paramValue[0]
			if paramName == visualizationNameParam {
				// user provided name of visualization for query
				name = tagValue
			} else {
				tags[paramName] = tagValue
			}
		}

		log.Logger.Debugf("%s call with query parameters: name='%s', tags='%s'",
			r.URL.Path, name, tags)

		result, err := handler.VisualizationsGet(clients, organizationID,
			name, tags)
		if err != nil {
			common.WriteErrorToResponse(w, http.StatusInternalServerError,
				http.StatusText(http.StatusInternalServerError),
				"Internal server error occured")
			log.Logger.Errorf("Error %s occured on handler func while"+
				"querying visualizations", err.Error())
		} else {
			serializedResult, serializationError := json.Marshal(result)
			if serializationError != nil {
				common.WriteErrorToResponse(w, http.StatusInternalServerError,
					http.StatusText(http.StatusInternalServerError),
					"Internal server error occured")
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(serializedResult)
		}
	}
}

// VisualizationsPost returns http handler with stored clients and handler pointers
func VisualizationsPost(clients *common.ClientContainer,
	handler common.HandlerInterface) func(http.ResponseWriter, *http.Request) {

	// all passed data would be validated by json-schema checker
	schemaLoader := gojsonschema.NewStringLoader(
		v1JsonSchema.VisualizationsCreateJSONSchema)
	return func(w http.ResponseWriter, r *http.Request) {
		// This function is triggered by router. All data has to be parsed
		// and validated, then handler function has to be called

		organizationID := r.Context().Value(common.OrganizationIDContext).(string)

		// validate data using jsonSchema
		bodyData, err := ioutil.ReadAll(r.Body)
		if err != nil {
			common.WriteErrorToResponse(w, http.StatusInternalServerError,
				http.StatusText(http.StatusInternalServerError),
				"Error reading request body")
			return
		}

		documentLoader := gojsonschema.NewStringLoader(string(bodyData))
		validationResult, err := gojsonschema.Validate(schemaLoader, documentLoader)
		if err != nil {
			// something is wrong with user json schema
			common.WriteErrorToResponse(w, http.StatusUnprocessableEntity,
				http.StatusText(http.StatusUnprocessableEntity),
				fmt.Sprintf("Error parsing json body '%s'", err))
			return
		}
		if !validationResult.Valid() {
			// provided json body does not correspond to json schema
			errorList := "["
			for _, desc := range validationResult.Errors() {
				errorList += desc.String()
			}
			errorList += "]"
			common.WriteErrorToResponse(w, http.StatusUnprocessableEntity,
				http.StatusText(http.StatusUnprocessableEntity),
				fmt.Sprintf("request body is not valid, list of erros %s", errorList))
			return
		}
		// data is validated - we can parse it and proceed
		payload := common.VisualizationPOSTData{}
		err = json.Unmarshal(bodyData, &payload)
		if err != nil {
			common.WriteErrorToResponse(w, http.StatusInternalServerError,
				http.StatusText(http.StatusInternalServerError),
				"Internal Server Error")
			return
		}
		result, err := handler.VisualizationsPost(clients, payload, organizationID)
		var encodedResult []byte
		if result != nil {
			serializedResult, serializationError := json.Marshal(result)
			if serializationError != nil {
				common.WriteErrorToResponse(w, http.StatusInternalServerError,
					http.StatusText(http.StatusInternalServerError),
					"Internal server error occured")
				return
			}
			encodedResult = serializedResult
		}
		if err != nil {
			log.Logger.Error(err)

			switch err.(type) {
			case common.UserDataError:
				common.WriteErrorToResponse(w, http.StatusUnprocessableEntity,
					http.StatusText(http.StatusUnprocessableEntity),
					fmt.Sprintf("Error rendering template '%s'", err))
				return
			case common.ClientError:
				// client failed right in the middle of dashboard
				// creation session, already created data was stored
				// in db, so we return it to user
				w.WriteHeader(http.StatusInternalServerError)
				w.Write(encodedResult)
				return
			default:
				common.WriteErrorToResponse(w, http.StatusInternalServerError,
					http.StatusText(http.StatusInternalServerError),
					"Internal server error occured")
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write(encodedResult)
	}
}

// VisualizationDelete returns http handler with stored clients and handler pointers
func VisualizationDelete(clients *common.ClientContainer,
	handler common.HandlerInterface) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// get visualizationId from url and validate, that it matches expected format
		visualizationID := chi.URLParam(r, "visualizationID")
		_, err := uuid.FromString(visualizationID)
		if err != nil {
			common.WriteErrorToResponse(w, http.StatusUnprocessableEntity,
				http.StatusText(http.StatusUnprocessableEntity),
				fmt.Sprintf("provided id does not match UUIDv4 format '%s'",
					visualizationID))
			return
		}
		organizationID := r.Context().Value(common.OrganizationIDContext).(string)

		var encodedResult []byte
		result, err := handler.VisualizationDelete(clients, organizationID, visualizationID)
		if result != nil {
			serializedResult, serializationError := json.Marshal(result)
			if serializationError != nil {
				common.WriteErrorToResponse(w, http.StatusInternalServerError,
					http.StatusText(http.StatusInternalServerError),
					"Internal server error occured")
				return
			}
			encodedResult = serializedResult
		}
		if err != nil {
			switch err.(type) {
			// visualization was not found in db
			case common.UserDataError:
				common.WriteErrorToResponse(w, http.StatusNotFound,
					http.StatusText(http.StatusNotFound),
					fmt.Sprintf("Requested visualization '%s' was not found",
						visualizationID))
				return
			case common.ClientError:
				w.WriteHeader(http.StatusInternalServerError)
				w.Write(encodedResult)
				return
			default:
				common.WriteErrorToResponse(w, http.StatusInternalServerError,
					http.StatusText(http.StatusInternalServerError),
					"Internal server error occured")
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write(encodedResult)
	}
}
