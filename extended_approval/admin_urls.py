"""Admin URLs for the extension."""

from django.conf.urls import url
from reviewboard.extensions.views import configure_extension

from extended_approval.extension import ExtendedApproval
from extended_approval.forms import ExtendedApprovalSettingsForm


urlpatterns = [
    url(r'^$', configure_extension, {
        'ext_class': ExtendedApproval,
        'form_class': ExtendedApprovalSettingsForm,
    }, name='extended_approval-configure'),
]
