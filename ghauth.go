package ghauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/go-github/github"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	ogh "golang.org/x/oauth2/github"
)

const githubUserKey = "gh-user-token"

// AuthManager is the core interface of this package. It is able to provide
// utility routes and authentication handlers.
type AuthManager interface {
	// Register necessary oauth routes at the specified paths.
	RegisterRoutes(login, callback, logout string, r gin.IRouter)
	// Middleware that checks cookie and sets user on context. Use on all routes.
	AuthCheck() gin.HandlerFunc
	// Middleware that will require login to access the route. Will redirect to login and attempt to
	// return to the same page on successful login.
	RequireAuth() gin.HandlerFunc
}

type GithubUser struct {
	Login     string
	ID        int
	AvatarURL string
	Token     string
}

func (g *GithubUser) Client() *github.Client {
	return client(g.Token)
}

func client(token string) *github.Client {
	c := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	return github.NewClient(c)
}

type authManager struct {
	hmac_key   []byte
	conf       *oauth2.Config
	aes        cipher.Block
	cookieName string
	loginRoute string
}

type Conf struct {
	ClientId     string
	ClientSecret string
	Scopes       []string
	CookieName   string
	CookieSecret string
}

func New(c *Conf) AuthManager {
	hmac_key := sha256.Sum256([]byte(c.CookieSecret))
	aes_key := sha256.Sum256([]byte(hmac_key[:]))

	conf := &oauth2.Config{
		Endpoint:     ogh.Endpoint,
		ClientID:     c.ClientId,
		ClientSecret: c.ClientSecret,
		Scopes:       c.Scopes,
	}

	aes, err := aes.NewCipher(aes_key[:])
	if err != nil {
		log.Fatal(err)
	}
	if c.CookieName == "" {
		c.CookieName = "ghuser"
	}
	return &authManager{aes: aes,
		hmac_key:   hmac_key[:],
		conf:       conf,
		cookieName: c.CookieName,
	}
}

type oauthState struct {
	RedirectPath string
	Random       []byte
}

func (a *authManager) RegisterRoutes(login, callback, logout string, r gin.IRouter) {
	a.loginRoute = login
	r.GET(login, func(ctx *gin.Context) {
		state := &oauthState{
			RedirectPath: ctx.DefaultQuery("redirect", "/"),
			Random:       make([]byte, 15),
		}
		rand.Read(state.Random)
		b, err := json.Marshal(state)
		if err != nil {
			return
		}
		stateStr := a.encrypt(b)
		rand.Read(state.Random)
		ctx.Redirect(302, a.conf.AuthCodeURL(stateStr))
	})
	r.GET(callback, func(ctx *gin.Context) {
		state := a.decrypt(ctx.Query("state"))
		if state == "" {
			ctx.Redirect(302, "/")
		}
		s := &oauthState{}
		if err := json.Unmarshal([]byte(state), s); err != nil {
			ctx.Redirect(302, "/")
		}
		tok, err := a.conf.Exchange(context.Background(), ctx.Query("code"))
		if err != nil {
			ctx.Redirect(302, "/")
		}
		c := client(tok.AccessToken)
		u, _, err := c.Users.Get("")
		if err != nil {
			ctx.Redirect(302, "/")
		}
		user := &GithubUser{
			Token:     tok.AccessToken,
			Login:     *u.Login,
			AvatarURL: *u.AvatarURL,
			ID:        *u.ID,
		}
		a.SetCookie(ctx, user)
		ctx.Redirect(302, s.RedirectPath)

	})
	r.GET(logout, func(ctx *gin.Context) {
		a.ClearCookie(ctx)
		ctx.Redirect(302, "/")
	})
}

func (a *authManager) AuthCheck() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		u := a.userFromCookie(ctx)
		ctx.Set(githubUserKey, u)
	}
}

func User(ctx *gin.Context) *GithubUser {
	if raw, ok := ctx.Get(githubUserKey); ok {
		return raw.(*GithubUser)
	}
	return nil
}

func (a *authManager) RequireAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		u := User(ctx)
		if u == nil {
			ctx.Redirect(302, a.loginRoute+"?redirect="+url.QueryEscape(ctx.Request.URL.String()))
			ctx.Abort()
		}
	}
}

func (a *authManager) userFromCookie(ctx *gin.Context) *GithubUser {
	cookie, err := ctx.Request.Cookie(a.cookieName)
	if err != nil {
		return nil
	}
	decrypted := a.decrypt(cookie.Value)
	if decrypted == "" {
		a.ClearCookie(ctx)
		return nil
	}
	u := &GithubUser{}
	if err = json.Unmarshal([]byte(decrypted), u); err != nil {
		return nil
	}
	return u
}

func (a *authManager) ClearCookie(ctx *gin.Context) {
	c := &http.Cookie{Name: a.cookieName, Value: "", Path: "/", Expires: time.Now().Add(-1 * time.Hour), MaxAge: -1}
	http.SetCookie(ctx.Writer, c)
}

func (a *authManager) SetCookie(ctx *gin.Context, u *GithubUser) {
	b, err := json.Marshal(u)
	if err != nil {
		return
	}
	cookieVal := a.encrypt(b)
	if cookieVal == "" {
		return
	}
	http.SetCookie(ctx.Writer, &http.Cookie{Name: a.cookieName, Secure: true, HttpOnly: true, Value: cookieVal, Path: "/", Expires: time.Now().Add(90 * 24 * time.Hour)})
}
