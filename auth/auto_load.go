package auth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"os"
	"strings"
)

const EnvSecret = "JWT_SECRET"

var Secret []byte

func init() {
	caddy.RegisterPlugin("auth", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

func ProvideKey(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
		return Secret, nil
	} else {
		return nil, fmt.Errorf("expect token signed with HMAC but got %v", token.Header["alg"])
	}
}

func Setup(c *caddy.Controller) error {

	secret := os.Getenv(EnvSecret)

	if len(secret) == 0 {
		return fmt.Errorf("environment variable %s not set", EnvSecret)
	}

	Secret = []byte(secret)

	rules, err := parse(c)

	if err != nil {
		return err
	}

	c.OnStartup(func() error {
		fmt.Println("JWT Auth middleware is initiated")
		return nil
	})

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &Auth{Next: next, Rules: rules}
	})

	return nil
}
func parse(c *caddy.Controller) ([]Rule, error) {
	rules := make([]Rule, 0)

	for c.Next() {
		args := c.RemainingArgs()
		rule := Rule{ExceptedPath: make([]string, 0)}
		switch len(args) {
		case 0:
			for c.NextBlock() {
				switch c.Val() {
				case "path":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}

					rule.Path = c.Val()

					if c.NextArg() {
						return nil, c.ArgErr()
					}

					break
				case "except":
					if !c.NextArg() {
						return nil, c.ArgErr()
					}

					rule.ExceptedPath = strings.Split(c.Val(), ",")

					for i := 0; i < len(rule.ExceptedPath); i++ {
						rule.ExceptedPath[i] = strings.TrimSpace(rule.ExceptedPath[i])
					}

					if c.NextArg() {
						return nil, c.ArgErr()
					}
					break
				}
			}
		case 1:
			rule.Path = args[0]
			rules = append(rules, rule)
			if c.NextBlock() {
				return nil, c.ArgErr()
			}
		default:
			return nil, c.ArgErr()
		}

		rules = append(rules, rule)
	}
	return rules, nil
}
