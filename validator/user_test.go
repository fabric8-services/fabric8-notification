package validator_test

import (
	"context"
	"strings"
	"testing"

	"github.com/fabric8-services/fabric8-notification/validator"
	"github.com/stretchr/testify/assert"
)

func TestValidateUserDeactivation(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		custom := make(map[string]interface{})
		custom["expiryDate"] = "May 2, 2019"
		custom["userEmail"] = "john-preview@example.com"
		err := validator.ValidateUserDeactivation(context.Background(), custom)
		assert.NoError(t, err)
	})

	t.Run("missing_expiry_date", func(t *testing.T) {
		custom := make(map[string]interface{})
		custom["userEmail"] = "john-preview@example.com"
		err := validator.ValidateUserDeactivation(context.Background(), custom)
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "expiryDate"), "Error message does not cotains '%s'", "expiryDate")
	})

	t.Run("nil_expiry_date", func(t *testing.T) {
		custom := make(map[string]interface{})
		custom["expiryDate"] = ""
		custom["userEmail"] = "john-preview@example.com"
		err := validator.ValidateUserDeactivation(context.Background(), custom)
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "expiryDate"), "Error message does not cotains '%s'", "expiryDate")
	})

	t.Run("missing_user_email", func(t *testing.T) {
		custom := make(map[string]interface{})
		custom["expiryDate"] = "May 2, 2019"
		err := validator.ValidateUserDeactivation(context.Background(), custom)
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "userEmail"), "Error message does not cotains '%s'", "userEmail")
	})

	t.Run("nil_user_email", func(t *testing.T) {
		custom := make(map[string]interface{})
		custom["expiryDate"] = "May 2, 2019"
		custom["userEmail"] = ""
		err := validator.ValidateUserDeactivation(context.Background(), custom)
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "userEmail"), "Error message does not cotains '%s'", "userEmail")
	})
}
