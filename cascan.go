package cascan

import (
	"github.com/casbin/casbin/v2"
	"github.com/gobuffalo/buffalo"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"log"
	"net/http"
	"strings"
	"sync"
)

var (
	a    *Authorizer
	once sync.Once
)

type userModel interface {
	GetAuthorizer() *Authorizer
	SetAuthorizer(a *Authorizer)
	GetRole() string
}

type Authorizer struct {
	enforcer   *casbin.Enforcer
	userModel  userModel
	policyFile string
	authModel  string

	mu sync.RWMutex
}

func (a *Authorizer) Authorize() buffalo.MiddlewareFunc {
	return func(next buffalo.Handler) buffalo.Handler {
		return func(c buffalo.Context) error {

			if a.userModel == nil {
				a.userModel = c.Value("current_user").(userModel)
			}

			if a.userModel.GetAuthorizer() == nil {
				a.userModel.SetAuthorizer(a)
			}

			role := a.userModel.GetRole()

			muxHandler := mux.CurrentRoute(c.Request()).GetHandler().(*buffalo.RouteInfo)

			resourceName := ""
			if muxHandler.ResourceName != "" {
				resourceName = strings.Split(muxHandler.ResourceName, "Resource")[0]
			}

			actionName := ""
			if muxHandler.HandlerName != "" {
				ss := strings.Split(muxHandler.HandlerName, "/actions.")
				actionName = ss[len(ss)-1]

				if strings.Contains(actionName, ".") {
					ssd := strings.Split(muxHandler.HandlerName, ".")
					actionName = ssd[len(ssd)-1]
				}
			}

			res, err := a.enforcer.Enforce(role, resourceName, actionName)
			if err != nil {
				return errors.WithStack(err)
			}
			if res {
				return next(c)
			}

			return c.Error(http.StatusUnauthorized, errors.New("You are unauthorized to perform the requested action"))
		}
	}
}

func NewAuthorizer(authModelFile string, policyFile string) *Authorizer {
	once.Do(func() {
		authEnforcer, err := casbin.NewEnforcer(authModelFile, policyFile)
		if err != nil {
			log.Fatal(err)
		}
		a = &Authorizer{
			enforcer:   authEnforcer,
			policyFile: policyFile,
			authModel:  authModelFile,
		}
	})
	return a
}

func (a *Authorizer) IsAuthorizedFor(resourceName string, actionName string) bool {
	res, _ := a.enforcer.Enforce(a.userModel.GetRole(), resourceName, actionName)
	return res
}
