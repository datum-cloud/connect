CONTROLLER_GEN ?= controller-gen

.PHONY: generate manifests test build deploy-render
generate:
	$(CONTROLLER_GEN) object paths=./api/...

manifests: generate
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=config/base/crd/bases
	$(CONTROLLER_GEN) rbac:roleName=connect-manager paths=./... output:rbac:artifacts:config=config/base/rbac

test:
	go test ./...

build:
	go build -o bin/connect-controller ./cmd/controller

deploy-render:
	kubectl kustomize config/default >/dev/null
