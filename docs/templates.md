# Simplified EZT templating

**asfquart** has built-in decorators to apply an EZT template to a route/handler
to generate an HTML response page from a "data dictionary".

EZT will take a template, and a data dictionary as inputs/value for that
template, to produce an HTML page. The decorator specifies the template,
and the function returns that data dictionary. These are combined and
used as the page response for the route/endpoint.

~~~python
import asfquart
APP = asfquart.APP

T_EXAMPLE = APP.load_template('templates/example.ezt')

@APP.use_template(T_EXAMPLE)
async def page_example():
    data = {
        'title': 'Example page',
        'count': 42,
        }
    return data
~~~

The `APP.load_template()` method will install a "watcher" on the source
file. Should it change, the template will be automatically reloaded
immediately. Its next rendering will use the changes, and no application
restart is necessary.

`load_template()` takes a path relative to `APP.app_dir` or an absolute path.
