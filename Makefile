GO = go
GO_FLAGS =
GOFMT = gofmt

DEP = dep

DOCKER = docker
GINKGO = ginkgo -p

NAME = lrolaz/certificate-init-container
REGISTRY = index.docker.io
VERSION=0.0.24
TAG = $(REGISTRY)/$(NAME):$(VERSION)

# TODO: Simplify this once ./... ignores ./vendor
GO_PACKAGES = .
GO_FILES := $(shell find $(shell $(GO) list -f '{{.Dir}}' $(GO_PACKAGES)) -name \*.go)

all: certificate-init-container.image

dep: 
	$(DEP) ensure

certificate-init-container: $(GO_FILES)
	env GOOS=linux $(GO) build -o $@ $(GO_FLAGS) .

certificate-init-container.image: Dockerfile certificate-init-container
	$(DOCKER) build -t $(REGISTRY)/$(NAME):$(VERSION)  -f Dockerfile .
	echo $(REGISTRY)/$(NAME):$(VERSION) >$@.tmp
	mv $@.tmp $@

test:
	$(GO) test $(GO_FLAGS) $(GO_PACKAGES)

fmt:
	$(GOFMT) -s -w $(GO_FILES)

clean:
	$(RM) ./certificate-init-container
	$(RM) ./certificate-init-container.image

.PHONY: all test clean vet fmt
