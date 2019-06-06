package template_test

import (
	"context"
	"fmt"
	"testing"

	"strings"

	"github.com/fabric8-services/fabric8-notification/auth"
	authApi "github.com/fabric8-services/fabric8-notification/auth/api"
	"github.com/fabric8-services/fabric8-notification/collector"
	"github.com/fabric8-services/fabric8-notification/template"
	"github.com/fabric8-services/fabric8-notification/testsupport"
	"github.com/fabric8-services/fabric8-notification/types"
	"github.com/fabric8-services/fabric8-notification/wit"
	witApi "github.com/fabric8-services/fabric8-notification/wit/api"
	"github.com/goadesign/goa/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	OpenshiftIOAPI     = "http://api.prod-preview.openshift.io"
	OpenShiftIOAuthAPI = "https://auth.prod-preview.openshift.io"
)

func addGlobalVars(vars map[string]interface{}) map[string]interface{} {
	vars["webURL"] = "http://localhost"
	return vars
}

func createClient(t *testing.T) (*witApi.Client, *authApi.Client) {
	c, err := wit.NewCachedClient(OpenshiftIOAPI)
	if err != nil {
		t.Fatal(err)
	}
	authClient, err := auth.NewCachedClient(OpenShiftIOAuthAPI)
	if err != nil {
		t.Fatal(err)
	}
	return c, authClient
}

func TestTrueOnFoundName(t *testing.T) {
	reg := template.AssetRegistry{}

	_, exist := reg.Get(string(types.WorkitemUpdate))
	assert.True(t, exist)
}

func TestFalseOnMissingName(t *testing.T) {
	reg := template.AssetRegistry{}

	_, exist := reg.Get("MISSING")
	assert.False(t, exist)
}

func TestRenderEmailUpdate(t *testing.T) {
	reg := template.AssetRegistry{}

	temp, exist := reg.Get(string(types.UserEmailUpdate))
	assert.True(t, exist)

	_, authClient := createClient(t)
	ciID, _ := uuid.FromString("1a3496ca-edc0-42f7-958f-ba02ed3ef54d")

	_, vars, err := collector.User(context.Background(), authClient, ciID)
	if err != nil {
		t.Fatal(err)
	}

	if vars == nil {
		vars = map[string]interface{}{}
	}
	vars["custom"] = map[string]interface{}{
		"verifyURL": "https://verift.url.openshift.io",
	}
	_, body, _, err := temp.Render(addGlobalVars(vars))
	require.NoError(t, err)
	assert.True(t, strings.Contains(body, "https://verift.url.openshift.io"))
}

func TestRenderCVE(t *testing.T) {
	files := []string{"cve.basic", "cve.many"}

	reg := template.AssetRegistry{}
	template, exist := reg.Get(string(types.AnalyticsNotifyCVE))
	assert.True(t, exist)

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			vars := make(map[string]interface{})
			payload, err := testsupport.GetFileContent(fmt.Sprintf("test-files/%s.json", file))
			require.NoError(t, err)
			vars["custom"] = testsupport.GetCustomElement(payload)

			sub, body, _, err := template.Render(addGlobalVars(vars))
			require.NoError(t, err)

			custom := toMap(vars["custom"])
			assert.True(t, strings.Contains(sub, toString(custom["repo_url"])))
			checkCVEBody(t, body, custom)
		})
	}
}

func TestRenderVersion(t *testing.T) {
	files := []string{"version"}
	reg := template.AssetRegistry{}
	template, exist := reg.Get(string(types.AnalyticsNotifyVersion))
	assert.True(t, exist)

	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			vars := make(map[string]interface{})
			payload, err := testsupport.GetFileContent(fmt.Sprintf("test-files/%s.json", file))
			require.NoError(t, err)

			vars["custom"] = testsupport.GetCustomElement(payload)

			sub, body, _, err := template.Render(addGlobalVars(vars))
			require.NoError(t, err)

			custom := toMap(vars["custom"])

			assert.True(t, strings.Contains(sub, toString(custom["repo_url"])))
			checkVersionBody(t, body, custom)
		})
	}
}

func TestRenderUserDeactivation(t *testing.T) {
	file := "user.deactivation"
	reg := template.AssetRegistry{}
	template, exist := reg.Get(string(types.UserDeactivation))
	assert.True(t, exist)

	vars := make(map[string]interface{})
	payload, err := testsupport.GetFileContent(fmt.Sprintf("test-files/%s.json", file))
	require.NoError(t, err)

	vars["custom"] = testsupport.GetCustomElement(payload)

	_, body, _, err := template.Render(addGlobalVars(vars))
	require.NoError(t, err)

	custom := toMap(vars["custom"])

	assert.True(t, strings.Contains(body, toString(custom["expiryDate"])), "Body does not contains '%s' expiryDate", toString(custom["expiryDate"]))
	assert.True(t, strings.Contains(body, toString(custom["userEmail"])), "Body does not contains '%s' userEmail", toString(custom["userEmail"]))
}

func checkCVEBody(t *testing.T, body string, custom map[string]interface{}) {
	t.Helper()
	assert.True(t, strings.Contains(body, toString(custom["repo_url"])))
	assert.True(t, strings.Contains(body, toString(custom["scanned_at"])))
	assert.True(t, strings.Contains(body, toString(custom["total_dependencies"])))
	dirDepArr := toArrMap(custom["direct_updates"])
	assert.NotNil(t, dirDepArr)
	transDepArr := toArrMap(custom["transitive_updates"])
	assert.NotNil(t, transDepArr)

	checkDepDataCVE(t, body, dirDepArr)
	checkDepDataCVE(t, body, transDepArr)

}

func checkDepDataCVE(t *testing.T, body string, deps []map[string]interface{}) {
	t.Helper()
	for _, dep := range deps {
		assert.True(t, strings.Contains(body, toString(dep["name"])))
		cveArr := toArrMap(dep["cves"])
		for _, cve := range cveArr {
			assert.True(t, strings.Contains(body, toString(cve["CVE"])))
			cvss := fmt.Sprintf("[%s/10]", toString(cve["CVSS"]))
			assert.True(t, strings.Contains(body, cvss))
		}
	}
}

func checkVersionBody(t *testing.T, body string, custom map[string]interface{}) {
	t.Helper()
	assert.True(t, strings.Contains(body, toString(custom["repo_url"])))
	assert.True(t, strings.Contains(body, toString(custom["scanned_at"])))
	assert.True(t, strings.Contains(body, toString(custom["git_pr"])))

	dirDepArr := toArrMap(custom["direct_updates"])
	assert.NotNil(t, dirDepArr)
	transDepArr := toArrMap(custom["transitive_updates"])
	assert.NotNil(t, transDepArr)
	checkDepData(t, body, dirDepArr)
	checkDepData(t, body, transDepArr)
}

func checkDepData(t *testing.T, body string, deps []map[string]interface{}) {
	t.Helper()
	for _, dep := range deps {
		assert.True(t, strings.Contains(body, toString(dep["name"])))
		assert.True(t, strings.Contains(body, toString(dep["version"])))
		assert.True(t, strings.Contains(body, toString(dep["latest_version"])))
		assert.True(t, strings.Contains(body, toString(dep["ecosystem"])))
	}
}

func toString(val interface{}) string {
	if str, ok := val.(string); ok {
		return str
	}
	return ""
}

func toMap(val interface{}) map[string]interface{} {
	if m, ok := val.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func toArrMap(val interface{}) []map[string]interface{} {
	if arr, ok := val.([]interface{}); ok {
		res := make([]map[string]interface{}, 0, 0)
		for _, e := range arr {
			val := toMap(e)
			if val != nil {
				res = append(res, val)
			} else {
				return nil
			}
		}
		return res
	}
	return nil
}
