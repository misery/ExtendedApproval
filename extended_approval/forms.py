from __future__ import unicode_literals

from django.forms import BooleanField, IntegerField
from djblets.extensions.forms import SettingsForm


class ExtendedApprovalSettingsForm(SettingsForm):
    grace_period_diffset = IntegerField(
        label='Grace period (Diffset) in seconds',
        help_text='Time to "last diffset" review request being approved.')

    grace_period_shipit = IntegerField(
        label='Grace period (Ship It!) in seconds',
        help_text='Time to "Ship It" review request being approved.')

    enable_revoke_shipits = BooleanField(
        required=False,
        label='Revoke previous ShipIts',
        help_text='Revoke all ShipIts after a new diff was uploaded.')
