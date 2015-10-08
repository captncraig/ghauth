<html>
<head>
<script src="//code.jquery.com/jquery-1.11.2.min.js"></script>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/css/bootstrap.min.css">
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/css/bootstrap-theme.min.css">
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/js/bootstrap.min.js"></script>
<title>Title</title>
</head>

<body>


<nav class="navbar navbar-default navbar-top">
  <div class="container">
    <div class="navbar-header">
      <a class="navbar-brand" href="/">
			Title
      </a>
    </div>
	
	<ul class="nav navbar-nav navbar-right">
		{{if .User}}
			<li><a href="https://github.com/{{.User.Login}}">{{.User.Login}}</a></li>
			<li><img src="{{.User.AvatarURL}}" width="40" style='margin-top:5px;'></img></li>
			<li><a href="/logout">Logout</a></li>
		{{else}}
        <li><a href="/login">Login</a></li>
		{{end}}
	</ul>
	
  </div>
</nav>

<div class='container'>
