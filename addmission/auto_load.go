package admission

import (
	"fmt"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"kubesphere.io/caddy-plugin/addmission/informer"
	"strings"
)

func init() {
	caddy.RegisterPlugin("admission", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

// Setup is called by Caddy to parse the config block
func Setup(c *caddy.Controller) error {

	rule, err := parse(c)

	if err != nil {
		return err
	}

	err = informer.Start()

	if err != nil {
		return err
	}

	c.OnStartup(func() error {
		fmt.Println("Admission middleware is initiated")
		return nil
	})

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &Admission{Next: next, Rule: rule}
	})
	return nil
}

func parse(c *caddy.Controller) (Rule, error) {

	rule := Rule{ExceptedPath: make([]string, 0)}

	if c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 0:
			for c.NextBlock() {
				switch c.Val() {
				case "path":
					if !c.NextArg() {
						return rule, c.ArgErr()
					}

					rule.Path = c.Val()

					if c.NextArg() {
						return rule, c.ArgErr()
					}

					break
				case "except":
					if !c.NextArg() {
						return rule, c.ArgErr()
					}

					rule.ExceptedPath = strings.Split(c.Val(), ",")

					for i := 0; i < len(rule.ExceptedPath); i++ {
						rule.ExceptedPath[i] = strings.TrimSpace(rule.ExceptedPath[i])
					}

					if c.NextArg() {
						return rule, c.ArgErr()
					}
					break
				}
			}
		case 1:
			rule.Path = args[0]
			if c.NextBlock() {
				return rule, c.ArgErr()
			}
		default:
			return rule, c.ArgErr()
		}
	}

	if c.Next() {
		return rule, c.ArgErr()
	}

	return rule, nil
}
