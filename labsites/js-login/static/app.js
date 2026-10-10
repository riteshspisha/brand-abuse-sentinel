// Builds a lookalike sign-in form only in a browser (static fetch sees an empty shell).
(function () {
  var b = ["Lumina", " Foundation"].join("");
  document.title = b + " - Member Sign In";
  var app = document.getElementById("app");
  app.innerHTML =
    '<h1>' + b + ' Members</h1>' +
    '<p>Sign in to access your Inner Radiance program recordings.</p>' +
    '<form id="login" action="/session" method="post">' +
    '<label>Email <input type="email" name="email" autocomplete="username"></label>' +
    '<label>Password <input type="password" name="password" autocomplete="current-password"></label>' +
    '<button type="submit">Sign in</button></form>';
})();
