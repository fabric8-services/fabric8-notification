package collector_test

import (
	"context"
	"testing"

	"github.com/fabric8-services/fabric8-notification/auth"
	authApi "github.com/fabric8-services/fabric8-notification/auth/api"
	"github.com/fabric8-services/fabric8-notification/collector"
	"github.com/fabric8-services/fabric8-notification/wit"
	witApi "github.com/fabric8-services/fabric8-notification/wit/api"
	"github.com/goadesign/goa/uuid"
	"github.com/stretchr/testify/assert"
)

const (
	OpenshiftIOAPI     = "http://api.prod-preview.openshift.io"
	OpenShiftIOAuthAPI = "https://auth.prod-preview.openshift.io"
)

func createClient(t *testing.T) (*witApi.Client, *authApi.Client) {
	c, err := wit.NewCachedClient(OpenshiftIOAPI)
	if err != nil {
		t.Fatal(err)
	}

	authApi, err := auth.NewCachedClient(OpenShiftIOAuthAPI)
	if err != nil {
		t.Fatal(err)
	}
	return c, authApi
}

func TestUser(t *testing.T) {
	_, authClient := createClient(t)
	uID, _ := uuid.FromString("1a3496ca-edc0-42f7-958f-ba02ed3ef54d")
	users, vars, err := collector.User(context.Background(), authClient, uID)

	assert.Nil(t, err)
	assert.Len(t, users, 1)
	assert.Len(t, vars, 0)
}
