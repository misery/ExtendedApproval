from __future__ import unicode_literals

from django.conf.urls import patterns, url


urlpatterns = patterns(
    'extended_approval.views',

    url(r'^$', 'configure'),
)
