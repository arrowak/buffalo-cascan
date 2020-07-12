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

type roleGetter func(buffalo.Context) (string, error)

var (
	a    *authorizer
	once sync.Once
)

type authorizer struct {
	enforcer   *casbin.Enforcer
	roleGetter roleGetter
	policyFile string
	authModel  string

	mu sync.RWMutex
}

func (a *authorizer) Authorize() buffalo.MiddlewareFunc {
	return func(next buffalo.Handler) buffalo.Handler {
		return func(c buffalo.Context) error {
			role, err := a.roleGetter(c)

			if err != nil {
				return errors.WithStack(err)
			}

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

func NewAuthorizer(authModelFile string, policyFile string, rGetter roleGetter) *authorizer {
	once.Do(func() {
		authEnforcer, err := casbin.NewEnforcer(authModelFile, policyFile)
		if err != nil {
			log.Fatal(err)
		}
		a = &authorizer{
			enforcer:   authEnforcer,
			roleGetter: rGetter,
			policyFile: policyFile,
			authModel:  authModelFile,
		}
	})
	return a
}
