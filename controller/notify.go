package controller

import (
	"context"
	"fmt"

	"github.com/fabric8-services/fabric8-notification/app"
	"github.com/fabric8-services/fabric8-notification/collector"
	"github.com/fabric8-services/fabric8-notification/email"
	"github.com/fabric8-services/fabric8-notification/jsonapi"
	"github.com/fabric8-services/fabric8-notification/template"
	"github.com/fabric8-services/fabric8-notification/token"
	"github.com/fabric8-services/fabric8-wit/errors"
	"github.com/fabric8-services/fabric8-wit/log"
	"github.com/goadesign/goa"
)

const (
	CVENotification             string = "analytics.notify.cve"
	UserEmailUpdateNotification string = "user.email.update"
)

var nTypeToSAMap = map[string]string{
	CVENotification:             "fabric8-gemini-server",
	UserEmailUpdateNotification: "fabric8-auth",
}

// NotifyController implements the notify resource.
type NotifyController struct {
	*goa.Controller
	CollectorRegistry collector.Registry
	TemplateRegistry  template.Registry
	Notifier          email.Notifier
}

// NewNotifyController creates a notify controller.
func NewNotifyController(service *goa.Service, cRegistry collector.Registry, tRegistry template.Registry, notifier email.Notifier) *NotifyController {
	return &NotifyController{Controller: service.NewController("NotifyController"), CollectorRegistry: cRegistry, TemplateRegistry: tRegistry, Notifier: notifier}
}

// Send runs the send action.
func (c *NotifyController) Send(ctx *app.SendNotifyContext) error {
	nType := ctx.Payload.Data.Attributes.Type
	if !checkAllowedSrvcAcc(ctx, nType) {
		return jsonapi.JSONErrorResponse(ctx, errors.NewUnauthorizedError(fmt.Sprintf("Wrong token for '%s' notification type", nType)))
	}

	nID := ctx.Payload.Data.Attributes.ID
	customAttributes := ctx.Payload.Data.Attributes.Custom

	var found bool
	var template template.Template
	var receiverResolver collector.ReceiverResolver

	validator, found := c.CollectorRegistry.Validator(nType)
	if found {
		err := validator(ctx, customAttributes)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
	}
	if template, found = c.TemplateRegistry.Get(nType); !found {
		log.Error(ctx, map[string]interface{}{
			"err":  "template type not found",
			"type": nType,
			"id":   nID,
		}, "resource requested")
		return jsonapi.JSONErrorResponse(ctx, errors.NewBadParameterError("data.attributes.type", nType))
	}
	if receiverResolver, found = c.CollectorRegistry.Get(nType); !found {
		log.Error(ctx, map[string]interface{}{
			"err":  "ReceiverResolver not found",
			"type": nType,
			"id":   nID,
		}, "resource requested")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, fmt.Errorf("could not find ReceiverResolver for type %v", nType)))
	}

	c.Notifier.Send(ctx, email.Notification{ID: nID, Type: nType, CustomAttributes: customAttributes, Resolver: receiverResolver, Template: template})

	return ctx.Accepted()
}

func checkAllowedSrvcAcc(ctx context.Context, nType string) bool {
	sa := nTypeToSAMap[nType]
	if sa != "" {
		return token.IsSpecificServiceAccount(ctx, sa)
	}
	return true
}
