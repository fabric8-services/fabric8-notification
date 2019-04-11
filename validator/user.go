package validator

import (
	"context"

	"github.com/fabric8-services/fabric8-common/errors"
)

func ValidateUser(context context.Context, custom map[string]interface{}) error {
	_, found := custom["verifyURL"]
	if !found {
		return errors.NewBadParameterError("data.attributes.custom.verifyURL", "nil")
	}
	return nil
}

func ValidateUserDeactivation(context context.Context, custom map[string]interface{}) error {
	_, found := custom["expiryDate"]
	if !found {
		return errors.NewBadParameterError("data.attributes.custom.expiryDate", "nil")
	}
	_, found = custom["userEmail"]
	if !found {
		return errors.NewBadParameterError("data.attributes.custom.userEmail", "nil")
	}
	return nil
}
