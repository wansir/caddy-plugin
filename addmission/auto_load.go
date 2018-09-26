package admission

import (
	"github.com/mholt/caddy"
	"kubesphere.io/caddy-plugin/addmission/informer"
	"fmt"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("admission", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}


// Setup is called by Caddy to parse the config block
func Setup(c *caddy.Controller) error {

	rules, err := parse(c)

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
		return &Admission{Next: next, Rules: rules}
	})
	return nil
}

func parse(c *caddy.Controller) ([]Rule, error) {
	rules := make([]Rule, 0)

	for c.Next() {
		args := c.RemainingArgs()
		rule := Rule{}
		switch len(args) {
		case 1:
			rule.Path = args[0]
			for c.NextBlock() {
				switch c.Val() {
				case "apiGroup":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					rule.APIGroup = c.Val()
					if c.NextArg() {
						return nil, c.ArgErr()
					}
					break
				case "resource":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}
					rule.Resource = c.Val()
					if c.NextArg() {
						return nil, c.ArgErr()
					}
					break
				}
			}
		default:
			return nil, c.ArgErr()
		}

		rules = append(rules, rule)
	}
	return rules, nil
}
