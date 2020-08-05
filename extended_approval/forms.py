from django.forms import CharField, BooleanField, IntegerField
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

    enable_target_shipits = BooleanField(
        required=False,
        label='Allow ShipIts of target groups/people only',
        help_text=('Do not accept ShipIts if the user is not in '
                   'review group/people.'))

    forbidden_user_shipits = CharField(
        required=False,
        label='User who can never ShipIt',
        help_text='Comma separated list of usernames.')
