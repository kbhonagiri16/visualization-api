package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/shuaiming/middlewares"
	log "visualization-api/pkg/logging"
)

// Proxy wapper ReverseProxy
type Proxy struct {
	proxy          *httputil.ReverseProxy
	requestLogging bool
	authHeader     string
}

// NewProxy New proxy
func NewProxy(endpoint string, requestLogging bool, authHeader string) (*Proxy, error) {
	backend, err := url.Parse(fmt.Sprintf("%s", endpoint))
	if err != nil {
		//TODO(illia) refactor logging package. Not very convenient to call log.Logger...
		log.Logger.Error("Can't parse Grafana url err: %s", err)
		return nil, err
	}
	log.Logger.Debugf("Grafana reverse proxy configured for endpoint=%s", endpoint)
	proxy := httputil.NewSingleHostReverseProxy(backend)
	return &Proxy{proxy: proxy, requestLogging: requestLogging, authHeader: authHeader}, nil
}

func (p *Proxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	sess := middlewares.GetSession(r)

	// overwrite grafana's logout
	if r.URL.Path == "/logout" {
		for k := range sess.Values {
			delete(sess.Values, k)
			err := sess.Save(r, rw)
			if err != nil {
				log.Logger.Errorf("Can't save sessions changes err: %s", err)
			}
		}
		log.Logger.Infof("Logging out user %s", sess.Values[SessionUsername])
		http.Redirect(rw, r, "/", http.StatusFound)
		return
	}

	log.Logger.Debugf("Proxying %s %s", r.Method, r.RequestURI)

	if _, ok := sess.Values[SessionUsername]; !ok {
		log.Logger.Errorf("%s key is expected to be defined in request "+
			"context. Looks like incorrect usage of middleware", SessionUsername)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return
	}

	//header for Grafana according to http://docs.grafana.org/installation/configuration/#auth-proxy
	r.Header.Set(p.authHeader, fmt.Sprintf("%s", sess.Values[SessionUsername]))

	if p.requestLogging {
		log.Logger.Debugf("Request dump  %v", r)
	}
	p.proxy.ServeHTTP(rw, r)
}
