package proxy

import (
	"github.com/kbhonagiri16/visualization-client"
	"github.com/shuaiming/middlewares"
	"net/http"
	log "visualization-api/pkg/logging"
)

// VisualizationAPIMiddleware creates users and organizations in Grafana
// via visualization-api according to model in session
type VisualizationAPIMiddleware struct {
	grafanaStateTTL int
	osHandler       *OpenStackAuthHandler
}

// NewVisualizationAPIMiddleware returns middleware for managing users and
// organizations in Grafana via Visualization API
func NewVisualizationAPIMiddleware(grafanaStateTTL int, osHandler *OpenStackAuthHandler) (*VisualizationAPIMiddleware, error) {
	return &VisualizationAPIMiddleware{grafanaStateTTL: grafanaStateTTL, osHandler: osHandler}, nil
}

func (vm *VisualizationAPIMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	log.Logger.Debugf("We are creating all users and organizations in this middleware")
	sess := middlewares.GetSession(r)

	if cmd, ok := sess.Values[GrafanaUpdateCommandSessionKey]; ok {
		log.Logger.Debugf("Visualization API command is %+v", cmd)
		log.Logger.Debugf("GrafanaUpdateCommandSessionKey %+v", GrafanaUpdateCommandSessionKey)

		username := sess.Values[SessionUsername]
		password := sess.Values[SessionPassword]
		isUserExists := sess.Values[UserExists]

		// Create User if not exitst
		if isUserExists == false {
			user := client.User{}
			user.Name = username.(string)
			user.Password = password.(string)
			user.Login = username.(string)
			user.Email = username.(string) + "@test.com"

			// Create User
			_, err := vm.osHandler.vclient.CreateUser(user)
			if err != nil {
				log.Logger.Errorf("Error creating user: %s", err)
				return
			}
		}

		delete(sess.Values, GrafanaUpdateCommandSessionKey)
		//saving cookies/session
		err := sess.Save(r, rw)
		if err != nil {
			log.Logger.Errorf("Can't save session change err: %s", err)
			http.Error(rw, "Internal error", http.StatusInternalServerError)
			return
		}
		next(rw, r)
		return
	}

	log.Logger.Debugf("Visualization API has been configured already for user. Skipping this step.")
	next(rw, r)
	return
}
