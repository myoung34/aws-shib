VERSION := $(shell git describe --tags --always --dirty="-dev")
LDFLAGS := -ldflags='-X "main.Version=$(VERSION)"'

release: gh-release govendor clean dist
	github-release release \
	--security-token $$GH_LOGIN \
	--user segmentio \
	--repo aws-shib \
	--tag $(VERSION) \
	--name $(VERSION)

	github-release upload \
	--security-token $$GH_LOGIN \
	--user segmentio \
	--repo aws-shib \
	--tag $(VERSION) \
	--name aws-shib-$(VERSION)-linux-amd64 \
	--file dist/aws-shib-$(VERSION)-linux-amd64

release-mac: gh-release govendor clean dist-mac
	github-release upload \
	--security-token $$GH_LOGIN \
	--user segmentio \
	--repo aws-shib \
	--tag $(VERSION) \
	--name aws-shib-$(VERSION)-darwin-amd64 \
	--file dist/aws-shib-$(VERSION)-darwin-amd64

clean:
	rm -rf ./dist

dist:
	mkdir dist
	govendor sync
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/aws-shib-$(VERSION)-linux-amd64

dist-mac:
	mkdir dist
	govendor sync
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/aws-shib-$(VERSION)-darwin-amd64

gh-release:
	go get -u github.com/aktau/github-release

govendor:
	go get -u github.com/kardianos/govendor
