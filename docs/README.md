# Bootstrapping asfquart

## Constructing the base quart app

```python
import asfquart


def main():
    app = asfquart.construct("name_of_app")
    return app


if __name__ == "__main__":
    app = main()
    # run a development server on port 8080
    app.runx(port=8080)
```

Other modules in the app will use:

```python
import asfquart

APP = asfquart.APP


@APP.some_decorator
async def some_endpoint():
    return do_something()
```

`asfquart.APP` is `None` until `construct()` has been called, though it is typed as the app.
Code that also runs in a process with no app, such as a worker or a script, calls
`asfquart.app_or_none()`, which is typed as returning the app or `None`:

```python
app = asfquart.app_or_none()
if app is not None:
    app.add_background_task(notify)
```

## One process

An asfquart application runs as one process: one instance, served by one worker. Do not give
the ASGI server more than one worker, and do not run several instances of an application
behind a load balancer. [One process](one-process.md) explains which parts of asfquart assume
this, what goes wrong otherwise, and what would have to change to support more.

## See also (WIP):

- [Setting up OAuth](oauth.md)
- [Behind a reverse proxy: HSTS, and what else the proxy has to do](reverse-proxy.md)
- [External services, and what happens when they fail](external-services.md)
- [Limits: how long, how large and how many](limits.md)
- [Session handling](sessions.md)
- [The application secret, and its token file](app-secret.md)
- [Authentication, Authorization, and Access](auth.md)
- [Session stores: keeping sessions on the server](session-stores.md)
- [Simplified EZT templating](templates.md)
- [Form data and its size limit](forms.md)
- [Input validation rules: what asfquart checks, and what it leaves to the application](input-validation.md)
