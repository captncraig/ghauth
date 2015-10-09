package ghauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
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

type AuthManager interface {
	RegisterRoutes(login, callback, logout string, r gin.IRouter)
	OpenHandler() gin.HandlerFunc
	LockedHandler() gin.HandlerFunc
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
	var aes_key, hmac_key [32]byte
	if c.CookieSecret != "" {
		hmac_key = sha256.Sum256([]byte(c.CookieSecret))
		aes_key = sha256.Sum256([]byte(hmac_key[:]))
	} else {
		var aes_key, hmac_key [32]byte
		rand.Read(aes_key[:])
		rand.Read(hmac_key[:])
	}
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

func (a *authManager) OpenHandler() gin.HandlerFunc {
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

func (a *authManager) LockedHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		u := a.userFromCookie(ctx)
		ctx.Set(githubUserKey, u)
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

func (a *authManager) encrypt(plaintext []byte) string {
	//encrypt then sign
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return ""
	}
	stream := cipher.NewCFBEncrypter(a.aes, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	hash := a.hash(ciphertext)
	a.hash(ciphertext)
	return base64.StdEncoding.EncodeToString(append(hash, ciphertext...))
}
func (a *authManager) hash(ciphertext []byte) []byte {
	h := hmac.New(sha256.New, a.hmac_key)
	_, err := h.Write(ciphertext)
	if err != nil {
		return []byte{}
	}
	m := h.Sum(nil)
	return m
}
func (a *authManager) decrypt(cookieData string) string {
	ciphertext, err := base64.StdEncoding.DecodeString(cookieData)
	if err != nil {
		return ""
	}
	if len(ciphertext) < sha256.Size+aes.BlockSize { //at least room for iv and hmac
		return ""
	}
	//first validate hmac
	msgMac := ciphertext[:sha256.Size]
	ciphertext = ciphertext[sha256.Size:]
	actualMac := a.hash(ciphertext)
	if !hmac.Equal(msgMac, actualMac) {
		return ""
	}
	// pull out iv and decrypt
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(a.aes, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext)
}
