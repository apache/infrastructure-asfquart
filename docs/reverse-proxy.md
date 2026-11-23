# Behind a reverse proxy

An asfquart application is normally run behind a reverse proxy such as httpd, which holds
the certificate and speaks HTTPS to the browser. Some things that look like the
application's business are the proxy's, because only the proxy knows the host name's
policy and who the client is. This page lists them.

## HTTPS, and Strict-Transport-Security

asfquart does not send a `Strict-Transport-Security` (HSTS) header. Set it at the proxy.

HSTS tells a browser to use HTTPS for a host name from then on, and to refuse to continue
past a certificate error there. It is a policy for the host name, so it belongs with
whatever serves that name's certificate. The application behind the proxy does not know
what else is served under the name, or whether it is being run for real or by a developer
with a self-signed certificate, and a browser that has seen the header holds the host to
it for as long as the header says.

With httpd, and `mod_headers` loaded:

```apache
<VirtualHost *:443>
    ServerName myapp.apache.org
    Header always set Strict-Transport-Security "max-age=31536000"
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
</VirtualHost>

<VirtualHost *:80>
    ServerName myapp.apache.org
    Redirect permanent / https://myapp.apache.org/
</VirtualHost>
```

- `max-age` is in seconds; the value above is a year. When setting it for a host for the
  first time, start with a short one, an hour say, and raise it once everything works:
  a browser cannot be told to forget a long one early.
- Add `includeSubDomains` only if every name under this one is served over HTTPS. That is
  for whoever looks after the domain to decide.
- `always` puts the header on error responses as well.
- The second block sends plain HTTP requests to HTTPS. HSTS only takes effect after a
  browser has received it over HTTPS, so the first request still needs the redirect.

The example leaves out the certificate, and the port and addresses are placeholders.

What asfquart does itself does not depend on the header. The session cookie is `Secure`,
so a browser never sends it over plain HTTP, and `SameSite=Strict`. The address that the
OAuth provider sends the browser back to is always `https`.

An application that serves HTTPS itself, with a certificate given to `run()` and no proxy,
has to add the header in a response hook of its own.

## What else the proxy has to do

| What | Why | See |
|---|---|---|
| Pass the `Host` header through unchanged (`ProxyPreserveHost On`) | The OAuth callback address is built from it, unless `callback_host` is set | [Setting up OAuth](oauth.md#configuration) |
| Limit how often a client may make requests | asfquart has no rate limit, and sees the proxy's address for every request | [Limits](limits.md#what-has-no-limit) |
| Overwrite `X-Forwarded-For`, if the application logs it | Otherwise it is whatever the client sent | [Setting up OAuth](oauth.md#logging-logins) |
| Send requests to one process | Pending logins and limits are kept in the process | [One process](one-process.md) |
