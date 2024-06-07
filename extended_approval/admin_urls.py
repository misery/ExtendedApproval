"""Admin URLs for the extension."""

from django.urls import path
from reviewboard.extensions.views import configure_extension

from extended_approval.extension import ExtendedApproval
from extended_approval.forms import ExtendedApprovalSettingsForm


urlpatterns = [
    path('',
         configure_extension,
         {
            'ext_class': ExtendedApproval,
            'form_class': ExtendedApprovalSettingsForm,
         }, name='extended_approval-configure'),
]
