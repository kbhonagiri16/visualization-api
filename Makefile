GOPATH=$(PWD)/.gopath
GO=GOPATH=$(GOPATH) go
GIT_SHA=$(shell git log -n 1 --pretty=format:%H)
VERSION := $(if $(VERSION),$(VERSION),0.0.0)
PROJECT_NAME=$(notdir $(basename $(PWD)))
CODE_SUBDIR=pkg
DOCKER_USERNAME ?= docker_username

clean:
	rm -rf $(GOPATH)

init:
	#dependency management
	mkdir -p .gopath
	$(GO) get github.com/spf13/viper
	$(GO) get github.com/spf13/pflag
	$(GO) get github.com/op/go-logging
	$(GO) get github.com/go-sql-driver/mysql
	$(GO) get github.com/go-xorm/xorm
	$(GO) get github.com/stretchr/testify/assert
	$(GO) get github.com/pressly/chi
	$(GO) get github.com/auth0/go-jwt-middleware
	$(GO) get github.com/dgrijalva/jwt-go
	$(GO) get github.com/kbhonagiri16/visualization-client
	$(GO) get github.com/gophercloud/gophercloud
	$(GO) get github.com/gophercloud/gophercloud/openstack
	$(GO) get github.com/gophercloud/gophercloud/openstack/identity/v3/tokens
	$(GO) get github.com/mitchellh/mapstructure
	$(GO) get github.com/golang/mock/gomock
	$(GO) get github.com/golang/mock/mockgen
	$(GO) get github.com/xeipuuv/gojsonschema
	$(GO) get github.com/satori/go.uuid
	$(GO) get -u github.com/ulule/deepcopier
	$(GO) get -u gopkg.in/alecthomas/gometalinter.v1
	$(GO) get github.com/rubenv/sql-migrate/...
	$(GO) get github.com/shuaiming/mung
	$(GO) get github.com/shuaiming/middlewares
	GOPATH=$(GOPATH) $(GOPATH)/bin/gometalinter.v1 --install
	# as soon as our application does not use relative imports - source code
	# has to be present in GOPATH to make lint work
	# as soon as we created isolated GOPATH - we have to create a symlink
	# from GOPATH to our source code
	mkdir -p $(GOPATH)/src/$(PROJECT_NAME)/
	ln -s $(PWD)/$(CODE_SUBDIR) $(GOPATH)/src/$(PROJECT_NAME)/$(CODE_SUBDIR)

stylecheck:
	if [ ! -z "$$($(GO) fmt ./pkg/...)" ]; then exit 1; fi

fmt:
	$(GO) fmt ./pkg/...

lint:
	GOPATH=$(GOPATH) $(GOPATH)/bin/gometalinter.v1 --disable=gotype \
		  --disable=errcheck --disable=gas --disable=gocyclo --exclude=mock --exclude=Mock \
		  --exclude='dynamic type' ./pkg/...

generate-mocks:
	mkdir -p ./pkg/openstack/mock
	GOPATH=$(GOPATH) $(GOPATH)/bin/mockgen -destination ./pkg/openstack/mock/mock.go visualization-api/pkg/openstack ClientInterface
	mkdir -p ./pkg/http_endpoint/common/mock
	GOPATH=$(GOPATH) $(GOPATH)/bin/mockgen -destination ./pkg/http_endpoint/common/mock/mock.go visualization-api/pkg/http_endpoint/common HandlerInterface,ClockInterface
	mkdir -p ./pkg/grafanaclient/mock
	GOPATH=$(GOPATH) $(GOPATH)/bin/mockgen -destination ./pkg/grafanaclient/mock/mock.go visualization-api/pkg/grafanaclient SessionInterface
	mkdir -p ./pkg/database/mock
	GOPATH=$(GOPATH) $(GOPATH)/bin/mockgen -destination ./pkg/database/mock/mock.go visualization-api/pkg/database DatabaseManager

clean-mocks:
	rm -r ./pkg/openstack/mock
	rm -r ./pkg/grafanaclient/mock
	rm -r ./pkg/http_endpoint/common/mock
	rm -r ./pkg/database/mock

test: generate-mocks
	$(GO) test ./pkg/...

test-integration:
	docker run --name=grafana-integration-test -d -p 3000:3000 grafana/grafana
	sleep 10
	curl -v -X POST -H "Content-Type: applciation/json" -d '{"name":"PV Service", "login":"pv_service", "password":"123123"}' http://admin:admin@localhost:3000/api/admin/users
	curl -v -X PUT -H "Content-Type: applciation/json" -d '{"isGrafanaAdmin":true}' http://admin:admin@localhost:3000/api/admin/users/2/permissions
	GRAFANA_URL=http://0.0.0.0:3000 GRAFANA_USER=pv_service GRAFANA_PASS=123123 $(GO) test -v visualization-api/pkg/grafanaclient -tags=integration	
	docker rm --force grafana-integration-test

build: fmt lint
	$(GO) build ./pkg/cmd/auth_proxy
	$(GO) build ./pkg/cmd/visualizationapi

build-all: fmt
	mkdir -p build/linux-amd64
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "-X main.version=$(VERSION) -X main.gitVersion=$(GIT_SHA)" -o $(PWD)/build/linux-amd64/visualizationapi ./pkg/cmd/visualizationapi
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "-X main.version=$(VERSION) -X main.gitVersion=$(GIT_SHA)" -o $(PWD)/build/linux-amd64/auth_proxy ./pkg/cmd/auth_proxy
	GOOS=linux GOARCH=amd64 $(GO) build -o $(PWD)/build/linux-amd64/sql-migrate github.com/rubenv/sql-migrate/sql-migrate

package-init:
	docker build -t com.mirantis.pv/build ./tools/build

package-clean:
	docker image rm -f com.mirantis.pv/build
	rm -rf build/deb/*

package:
	docker run -e VERSION=$(VERSION) -v $(PWD):/app com.mirantis.pv/build /app/tools/build/build_deb.sh

package-debug:
	docker run -it -v $(PWD):/app com.mirantis.pv/build /bin/bash

docker:
	docker build -t $(DOCKER_USERNAME)/visualization-api -f tools/docker/visualization-api/Dockerfile .

docker-push:
	docker push $(DOCKER_USERNAME)/visualization-api

all: init fmt lint  build-all package-init package docker
