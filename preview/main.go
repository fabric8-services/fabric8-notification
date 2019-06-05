package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fabric8-services/fabric8-notification/auth"
	authapi "github.com/fabric8-services/fabric8-notification/auth/api"
	"github.com/fabric8-services/fabric8-notification/collector"
	"github.com/fabric8-services/fabric8-notification/template"
	"github.com/fabric8-services/fabric8-notification/testsupport"
	"github.com/fabric8-services/fabric8-notification/types"
	"github.com/fabric8-services/fabric8-notification/wit"
	"github.com/fabric8-services/fabric8-notification/wit/api"
	"github.com/goadesign/goa/uuid"
)

const (
	OpenshiftIOAPI     = "https://api.prod-preview.openshift.io"
	AuthOpenShiftIOAPI = "https://auth.prod-preview.openshift.io"
)

func main() {
	c, err := wit.NewCachedClient(OpenshiftIOAPI)
	authClient, err := auth.NewCachedClient(AuthOpenShiftIOAPI)
	if err != nil {
		panic(err)
	}

	type data struct {
		id           string
		templateName string
	}

	testdata := []data{
		{"1a3496ca-edc0-42f7-958f-ba02ed3ef54d", string(types.UserEmailUpdate)},
		{"1a3496ca-edc0-42f7-958f-ba02ed3ef54d", string(types.UserDeactivation)},
		{"1a3496ca-edc0-42f7-958f-ba02ed3ef54d", string(types.AnalyticsNotifyCVE)},
		{"1a3496ca-edc0-42f7-958f-ba02ed3ef54d", string(types.AnalyticsNotifyVersion)},
	}
	fmt.Println("Generating test templates..")
	fmt.Println("")

	for _, d := range testdata {
		err = generate(authClient, c, d.id, d.templateName)
		if err != nil {
			fmt.Printf(err.Error())
		}
	}
}

func generate(authClient *authapi.Client, c *api.Client, id, tmplName string) error {
	reg := template.AssetRegistry{}

	tmpl, exist := reg.Get(tmplName)
	if !exist {
		return fmt.Errorf("template %v not found", tmplName)
	}

	wiID, _ := uuid.FromString(id)

	vars := make(map[string]interface{})
	var err error

	// When running locally the actor ID has to be mocked
	// since there is no real actor.
	if strings.HasPrefix(tmplName, "user.deactivation") {
		vars["custom"] = map[string]interface{}{
			"userEmail":  "user@example.com",
			"expiryDate": time.Now().Add(7 * 24 * time.Hour).Format("Jan 2, 2006"),
		}
	} else if strings.HasPrefix(tmplName, "user") {
		_, vars, err = collector.User(context.Background(), authClient, wiID)
		vars["custom"] = map[string]interface{}{
			// a realistic verifyURL
			"verifyURL": "https://auth.prod-preview.openshift.io/api/users/verifyemail?code=580f7d71-853c-48df-8206-d1265bcf44f1",
		}
	} else if strings.HasPrefix(tmplName, "analytics.notify.cve") {
		vars = make(map[string]interface{})
		payload, err := testsupport.GetFileContent("preview/test-files/cve.payload.json")
		if err == nil {
			vars["custom"] = testsupport.GetCustomElement(payload)
		}
	} else if strings.HasPrefix(tmplName, "analytics.notify.version") {
		vars = make(map[string]interface{})
		payload, err := testsupport.GetFileContent("preview/test-files/version.payload.json")
		if err == nil {
			vars["custom"] = testsupport.GetCustomElement(payload)
		}
	} else {
		return fmt.Errorf("Unkown resolver for template %v", tmplName)
	}

	if err != nil {
		if len(vars) == 0 {
			return err
		}
	}

	fileName, err := filepath.Abs("tmp/" + tmplName + "-" + id + ".html")
	if err != nil {
		return err
	}
	subject, body, headers, err := tmpl.Render(addGlobalVars(vars))
	if err != nil {
		return err
	}
	fmt.Println("Subject:", subject)
	fmt.Println("Output :", "file://"+fileName)
	fmt.Println("Headers:")
	for k, v := range headers {
		fmt.Println(k, v)
	}
	fmt.Println("")

	ioutil.WriteFile(fileName, []byte(body), os.FileMode(0777))
	return nil
}

func addGlobalVars(vars map[string]interface{}) map[string]interface{} {
	vars["webURL"] = "https://openshift.io"
	return vars
}
