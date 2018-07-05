package collector

import (
	"context"

	authapi "github.com/fabric8-services/fabric8-notification/auth/api"
	"github.com/fabric8-services/fabric8-notification/wit/api"
)

func NewCVEResolver(authClient *authapi.Client, witClient *api.Client) ReceiverResolver {
	return func(ctx context.Context, id string) ([]Receiver, map[string]interface{}, error) {
		var values = map[string]interface{}{}
		return nil, values, nil
	}
}
