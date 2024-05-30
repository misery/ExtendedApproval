from django.forms import CharField, BooleanField, IntegerField, Textarea
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

    enable_legacy_buttons = BooleanField(
        required=False,
        label='Show legacy buttons on review request',
        help_text=('Shows old "Review", "General Comment" and "ShipIt".'))

#    enable_wait_it_button = BooleanField(
#        required=False,
#        label='Show "Wait It" button on review request',
#        help_text=('Shows custom "ShipIt" button with added issue.'))

    forbidden_user_shipits = CharField(
        required=False,
        label='User who can never ShipIt',
        help_text='Comma separated list of usernames.')

    forbidden_approve_prefixes = CharField(
        required=False,
        label='Non approvable commit message prefixes',
        help_text='A prefix per line separated optionally '
                  'by a | for a comment. '
                  'Example: WIP|work in progress',
        widget=Textarea(attrs={'cols': '80', 'rows': '10'}))

    forbidden_approve_suffixes = CharField(
        required=False,
        label='Non approvable commit message suffixes',
        help_text='A suffix per line separated optionally '
                  'by a | for a comment. '
                  'Example: (Topic)|Topics cannot be published',
        widget=Textarea(attrs={'cols': '80', 'rows': '10'}))
