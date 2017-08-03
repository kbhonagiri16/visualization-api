package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	gologging "github.com/op/go-logging"
	"visualization-api/pkg/auth_proxy"
	logging "visualization-api/pkg/logging"

	"github.com/shuaiming/mung"
	"github.com/shuaiming/middlewares"
	"github.com/shuaiming/middlewares/sessions"
)

var (
	logRotate *logging.RotateWriter
	log       *gologging.Logger

	version    = "UNDEFINED"
	gitVersion = "UNDEFINED"

	//app level flags
	versionParam = flag.Bool("version", false, "Prints version information")
)

// OpenstackConfigs for getting openstack token
var OpenstackConfigs struct {
	OpenstackEndpoint string
	Username          string
	Password          string
	Domain            string
	Project           string
}

func init() {
	viper.SetConfigName("auth_proxy") // name of config file (without extension)
	viper.AddConfigPath("./etc/platformvisibility/auth_proxy/")
	viper.AddConfigPath("/etc/platformvisibility/auth_proxy/") // path to look for the config file in
	err := viper.ReadInConfig()                                // Find and read the config file
	if err != nil {                                            // Handle errors reading the config file
		fmt.Printf("Fatal error config file: %s \n", err)
		os.Exit(1)
	}

	// Openstack environment variables
	flag.StringVar(&OpenstackConfigs.OpenstackEndpoint, "openstackEndpoint", viper.GetString("openstack.auth_url"), "Gets openstack endpoint")
	flag.StringVar(&OpenstackConfigs.Username, "username", viper.GetString("openstack.username"), "Openstack username")
	flag.StringVar(&OpenstackConfigs.Password, "password", viper.GetString("openstack.password"), "Openstack password")
	flag.StringVar(&OpenstackConfigs.Domain, "domain", viper.GetString("openstack.domain_name"), "Openstack domain")
	flag.StringVar(&OpenstackConfigs.Project, "project", viper.GetString("openstack.project_name"), "Openstack project")
}

func cleanupOnExit() {
	// this function is used to perform all cleanup on application exit
	// such as file descriptor close
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigc
		log.Info("Caught signal '", s, "' shutting down")
		// close global descriptor
		logRotate.Lock.Lock()
		defer logRotate.Lock.Unlock()
		err := logRotate.Fp.Close()
		if err != nil {
			fmt.Printf("Error during closing log file err: %s \n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}()
}

func main() {

	flag.Parse()

	if *versionParam {
		fmt.Printf("auth_proxy version %s %s \n", version, gitVersion)
		os.Exit(0)
	}

	loggerInit()
	log.Infof("auth_proxy version %s %s", version, gitVersion)
	cleanupOnExit()

	port := viper.GetString("http_endpoint.port")
	grafanaEndpoint := viper.GetString("grafana.endpoint")
	requestLogging := viper.GetBool("log.request_logging")
	authHeader := viper.GetString("grafana.auth_header")
	loginPagePath := viper.GetString("http_endpoint.login_page")
	visualizationEndpoint := viper.GetString("visualization_api.endpoint")

	loginPage, err := ioutil.ReadFile(loginPagePath)
	if err != nil {
		log.Errorf("Can't read login page content from %s", loginPagePath)
		os.Exit(0)
	}

	//
	// http goes here
	//

	sessionStore := sessions.NewCookieStore([]byte(viper.GetString("cookies.secret")))
	sessionStore.MaxAge(viper.GetInt("cookies.max_age"))

	sessionMgr := middlewares.NewSessions(sessionStore)

	p, err := proxy.NewProxy(grafanaEndpoint, requestLogging, authHeader)
	if err != nil {
		log.Errorf("Can't initialize grafana proxy err: %s", err)
		os.Exit(0)
	}

	prx := middlewares.NewHandler(p)

	//TODO(illia) get role mapping from config file
	osHandler, err := proxy.NewOpenStackAuthHandler(loginPage, viper.GetInt("cookies.grafana_state_ttl"), visualizationEndpoint, grafanaEndpoint, OpenstackConfigs, nil)

	if err != nil {
		log.Errorf("Can't initialize OpenStack middleware. err: %s", err)
		os.Exit(0)
	}

	vapiM, err := proxy.NewVisualizationAPIMiddleware(viper.GetInt("cookies.grafana_state_ttl"), osHandler)
	if err != nil {
		log.Errorf("Can't initialize visualization middleware")
		os.Exit(0)
	}

	app := mung.New()
	app.Use(sessionMgr)
	app.Use(osHandler)
	app.Use(vapiM)
	app.Use(prx)

	log.Infof("Starting HTTP server on %s", port)
	app.Run(fmt.Sprintf(":%s", port))

	if err != nil {
		log.Errorf("Error during creation HTTP server %s", err)
	}
}

func loggerInit() {
	logFilePath := viper.GetString("log.path")
	logLevel := viper.GetString("log.level")

	var err error
	logRotate, err = logging.NewRotateWriter(logFilePath)

	if err != nil {
		fmt.Printf("Can't initializa log file err: %s \n", err)
		os.Exit(1)
	}
	logging.InitializeLogger(logRotate, true, logLevel)
	log = logging.Logger
}
