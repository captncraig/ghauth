{{template "header.tpl" .}}

Home page! {{if .User}} Logged in as {{.User.Login}}. <a href="/logout">Log out</a>{{else}} Logged out. <a href="/login">Log in!</a> {{end}}

{{if .Repos}}
<h3>Your repositories: </h3>
<ul>
{{range .Repos}}
	<li><a href="/repo/{{.FullName}}">{{.FullName}}</a></li>
{{end}}
</ul>
{{end}}