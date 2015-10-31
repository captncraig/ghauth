# ghauth

[![GoDoc](https://godoc.org/github.com/captncraig/ghauth?status.svg)](http://godoc.org/github.com/captncraig/ghauth)


[Gin](https://github.com/gin-gonic/gin) middleware/handler for handling authentication to github via oauth.

- Seamlessly manages oauth flow to github.
- Securely stores oauth tokens in cookies.
- Middleware for requiring access / redirecting to login, or for unrestricted routes.

## Usage

```
func main() {
	r := gin.Default()
	r.LoadHTMLGlob("templates/*.tpl")

	// first create the auth handler
	conf := &ghauth.Conf{
		ClientId:     os.Getenv("GH_CLIENT_ID"),
		ClientSecret: os.Getenv("GH_CLIENT_SECRET"),
		Scopes:       []string{"user", "read:public_key", "repo"},
		CookieName:   "ghuser",
		CookieSecret: "any random string can go here, but make sure it is truly random and secret to secure your cookies",
	}
	auth := ghauth.New(conf)

	// register oauth routes
	auth.RegisterRoutes("/login", "/oauth", "/logout", r)
	// add the token reading middleware to all requests.
	r.Use(auth.AuthCheck())
	// all unauthorized routes can go here. Will still have user populated if logged in
	r.GET("/", home)

	// require authorization for these routes. Will redirect to login if not logged-in
	authRequired := r.Group("/", auth.RequireAuth())
	authRequired.GET("/repo/:owner/:repo", repo)

	r.Run(":8080") // listen and serve on 0.0.0.0:8080
}
```

In any handler you can then get the logged in user from any handler that uses the middleware by calling `ghauth.User(ctx)`. If the user is not logged in. It will be null.
