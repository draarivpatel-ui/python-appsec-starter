"""Django settings integration example.

Add the middleware near the top of ``MIDDLEWARE`` in your own project:

MIDDLEWARE = [
    "appsec_starter.adapters.django.AppSecDjangoMiddleware",
    # existing middleware entries follow
]
"""

from appsec_starter.adapters.django import AppSecDjangoMiddleware


def example_configuration():
    return ["appsec_starter.adapters.django.AppSecDjangoMiddleware"]
