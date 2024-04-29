# Simplified EZT templating

*asfquart* has built-in decorators to apply an EZT template to a route/handler
to generate an HTML response page from a "data dictionary".

EZT will take a template, and a data dictionary as inputs/value for that
template, to produce an HTML page. The decorator specifies the template,
and the function returns that data dictionary. These are combined and
used as the page response for the route/endpoint.

~~~python
import asfquart
APP = asfquart.APP

T_EXAMPLE = APP.load_template(APP.app_dir / 'templates/example.ezt')

@APP.use_template(T_EXAMPLE):
async def page_example():
    data = {
        'title': 'Example page',
        'count': 42,
        }
    return data
~~~
