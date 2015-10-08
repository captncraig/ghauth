{{template "header.tpl" .}}

<h3>{{.FullName}} pull requests:</h3>

<ul>
{{range .Pulls}}
<li><a href="{{.HTMLURL}}">{{.Number}} - {{.Title}}</a></li>

{{end}}
</ul>