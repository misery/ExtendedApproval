from __future__ import unicode_literals

from django.conf.urls import patterns, url

from extended_approval.extension import ExtendedApproval
from extended_approval.forms import ExtendedApprovalSettingsForm

urlpatterns = patterns(
    '',

    url(r'^$',
        'reviewboard.extensions.views.configure_extension',
        {
            'ext_class': ExtendedApproval,
            'form_class': ExtendedApprovalSettingsForm,
        },
        name='extended_approval-configure'),
)
