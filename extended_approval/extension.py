import pytz
from datetime import datetime, timedelta

from djblets.datagrid.grids import Column

from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _

from reviewboard.admin.read_only import is_site_read_only_for
from reviewboard.extensions.base import Extension
from reviewboard.extensions.hooks import (ActionHook,
                                          DataGridColumnsHook,
                                          DashboardColumnsHook,
                                          HideActionHook,
                                          ReviewRequestApprovalHook,
                                          SignalHook)
from reviewboard.datagrids.grids import ReviewRequestDataGrid
from reviewboard.reviews.actions import (BaseAction, ShipItAction)
from reviewboard.reviews.features import general_comments_feature
from reviewboard.reviews.signals import (review_publishing,
                                         review_request_published)
from reviewboard.urls import reviewable_url_names, review_request_url_names

all_review_request_url_names = reviewable_url_names + review_request_url_names

CONFIG_GRACE_PERIOD_DIFFSET = 'grace_period_diffset'
CONFIG_GRACE_PERIOD_SHIPIT = 'grace_period_shipit'
CONFIG_ENABLE_REVOKE_SHIPITS = 'enable_revoke_shipits'
CONFIG_ENABLE_TARGET_SHIPITS = 'enable_target_shipits'
CONFIG_ENABLE_LEGACY_BUTTONS = 'enable_legacy_buttons'
CONFIG_ENABLE_WAIT_IT_BUTTON = 'enable_wait_it_button'
CONFIG_FORBIDDEN_USER_SHIPITS = 'forbidden_user_shipits'
CONFIG_FORBIDDEN_APPROVE_PREFIXES = 'forbidden_approve_prefixes'
CONFIG_FORBIDDEN_APPROVE_PREFIXES_DICT = 'forbidden_approve_prefixes_dict'


class ReqReviews(object):
    def __init__(self, r):
        self.request = r
        self.diffset = r.get_latest_diffset()
        self.total = []
        self.latest = []
        self.self = []
        self.revoked = None

        if self.diffset:
            shipit_reviews = r.reviews.filter(public=True, ship_it=True)
            for shipit in shipit_reviews:
                if r.submitter == shipit.user:
                    self.self.append(shipit)
                else:
                    self.total.append(shipit)

                    if shipit.timestamp > self.diffset.timestamp:
                        self.latest.append(shipit)

    def getDiffset(self):
        return self.diffset

    def getSelf(self):
        return self.self

    def getRevoked(self):
        if self.revoked is None:
            self.revoked = []
            if self.diffset:
                reviews = self.request.reviews.filter(public=True,
                                                      ship_it=False)
                for shipit in reviews:
                    if self.request.submitter != shipit.user:
                        e = shipit.extra_data
                        if 'revoked_ship_it' in e and e['revoked_ship_it']:
                            self.revoked.append(shipit)
        return self.revoked

    def getTotal(self):
        return self.total

    def getTotalUser(self):
        return self._distinct_user(self.total)

    def getLatest(self):
        return self.latest

    def getLatestUser(self):
        return self._distinct_user(self.latest)

    def _distinct_user(self, sourceList):
        distinct = []
        for r in sourceList:
            if r.user not in distinct:
                distinct.append(r.user)
        return distinct


def calc_epoch(settings, config, obj):
    period = settings.get(config)

    if period is None:
        return obj.timestamp

    return obj.timestamp + timedelta(0, period)


def check_grace_period(settings, diffset, shipit):
    now = datetime.utcnow().replace(tzinfo=pytz.utc)

    epoch = calc_epoch(settings, CONFIG_GRACE_PERIOD_DIFFSET, diffset)
    if epoch > now:
        return ('Grace period for latest diff is not reached: %s'
                % epoch.strftime("%x %X %Z"))

    epoch = calc_epoch(settings, CONFIG_GRACE_PERIOD_SHIPIT, shipit)
    if epoch > now:
        return ('Grace period for approved "Ship It!" is not reached: %s'
                % epoch.strftime("%x %X %Z"))

    return None


def shipit_user_forbidden(settings, user):
    setting = settings.get(CONFIG_FORBIDDEN_USER_SHIPITS)
    forbidden = setting.strip().lower().split(',')
    return user.username.lower() in forbidden


def shipit_target_forbidden(settings, user, review_request):
    return settings.get(CONFIG_ENABLE_TARGET_SHIPITS) and (
            not review_request.target_groups.filter(users__pk=user.pk).exists()
            and not review_request.target_people.filter(pk=user.pk).exists()
           )


def shipit_forbidden(settings, user, review_request):
    return user == review_request.owner or \
           shipit_user_forbidden(settings, user) or \
           shipit_target_forbidden(settings, user, review_request)


class ApprovalColumn(Column):
    """Shows the approved state for a review request."""
    def __init__(self, extension, *args, **kwargs):
        """Initialize the column."""
        super(ApprovalColumn, self).__init__(
            image_class='rb-icon rb-icon-warning',
            image_alt=_('Approved'),
            detailed_label=_('Approved'),
            db_field='shipit_count',
            sortable=False,
            shrink=True,
            *args, **kwargs)

        self.settings = extension.settings

    def _render(self, details):
        return mark_safe(''.join(
                format_html(
                    '<div class="rb-icon rb-icon-{icon_name}"'
                    '      title="{title}" style="{style}"></div>',
                    **dict({'style': '', }, **detail))
                for detail in details
            ))

    def render_data(self, state, review_request):
        prefixes = self.settings[CONFIG_FORBIDDEN_APPROVE_PREFIXES_DICT]
        for key, value in prefixes.items():
            if review_request.summary.startswith(key):
                return self._render([{
                        'icon_name': 'issue-dropped',
                        'title': _(value),
                }])

        r = ReqReviews(review_request)
        if len(r.getTotal()) > 0 or len(r.getRevoked()) > 0:
            if len(r.getLatest()) > 0:
                period = check_grace_period(self.settings, r.getDiffset(),
                                            r.getLatest()[0])

                if period is not None:
                    return self._render([{
                              'icon_name': 'admin-disabled',
                              'title': period,
                       }])

                elif review_request.approved:
                    return self._render([{
                              'icon_name': 'admin-enabled',
                              'title': _('Approved'),
                       }])

                elif (review_request.issue_open_count > 0 or
                      review_request.issue_verifying_count > 0):
                    return self._render([{
                              'icon_name': 'admin-enabled',
                              'title': _('Approved but has issues'),
                              'style': 'filter: sepia(1)'
                       }])

            else:
                return self._render([{
                          'icon_name': 'issue-verifying',
                          'title': _('Latest diff not marked "Ship It!"'),
                   }])

        return self._render([{
                      'icon_name': 'issue-open',
                      'title': _('Not approved'),
               }])


class ConfigurableApprovalHook(ReviewRequestApprovalHook):
    def __init__(self, extension, *args, **kwargs):
        super(ConfigurableApprovalHook, self).__init__(
            extension, *args, **kwargs)
        self.settings = extension.settings

    def is_approved(self, review_request, prev_approved, prev_failure):
        if (review_request.issue_open_count > 0 or
           review_request.issue_verifying_count > 0):
            return False, 'The review request has open issues'

        prefixes = self.settings[CONFIG_FORBIDDEN_APPROVE_PREFIXES_DICT]
        for key, value in prefixes.items():
            if review_request.summary.startswith(key):
                return False, 'The review request is marked as "%s"' % value

        if not prev_approved:
            return False, prev_failure

        r = ReqReviews(review_request)
        if len(r.getLatest()) == 0:
            return False, 'The latest diff has not been marked' \
                          ' "Ship It!" by someone else'

        period = check_grace_period(self.settings, r.getDiffset(),
                                    r.getLatest()[0])
        if period is not None:
            return False, period

        return True


class AdvancedShipItAction(ShipItAction):
    action_id = 'advanced-ship-it'

    def __init__(self, settings):
        super(AdvancedShipItAction, self).__init__()
        self.settings = settings

    def should_render(self, context):
        return (super().should_render(context=context) and
                not shipit_forbidden(self.settings,
                                     context['request'].user,
                                     context['review_request']))


class AdvancedPingItAction(ShipItAction):
    action_id = 'advanced-ping-it'
    label = _('Ping It!')
    description = [
        _("You're happy with what you're seeing, and would like to "
          'request a ShipIt.'),
    ]

    def __init__(self, settings):
        super(AdvancedPingItAction, self).__init__()
        self.settings = settings

    def should_render(self, context):
        return (super().should_render(context=context) and
                shipit_forbidden(self.settings,
                                 context['request'].user,
                                 context['review_request']))


class AdvancedLegacyEditReviewAction(BaseAction):
    action_id = 'advanced-legacy-edit-review'
    label = _('Review')
    apply_to = all_review_request_url_names
    js_view_class = 'RB.CreateReviewActionView'

    def __init__(self, settings):
        super(AdvancedLegacyEditReviewAction, self).__init__()
        self.settings = settings

    def should_render(self, context):
        request = context['request']
        user = request.user
        return (self.settings.get(CONFIG_ENABLE_LEGACY_BUTTONS) and
                super().should_render(context=context) and
                user.is_authenticated and
                not is_site_read_only_for(user))


class AdvancedLegacyAddGeneralCommentAction(BaseAction):
    action_id = 'advanced-legacy-add-general-comment'
    label = _('Add General Comment')
    apply_to = all_review_request_url_names
    js_view_class = 'RB.AddGeneralCommentActionView'

    def __init__(self, settings):
        super(AdvancedLegacyAddGeneralCommentAction, self).__init__()
        self.settings = settings

    def should_render(self, context):
        request = context['request']
        user = request.user
        return (self.settings.get(CONFIG_ENABLE_LEGACY_BUTTONS) and
                super().should_render(context=context) and
                user.is_authenticated and
                not is_site_read_only_for(user) and
                general_comments_feature.is_enabled(request=request))


class AdvancedLegacyShipItAction(BaseAction):
    action_id = 'advanced-legacy-ship-it'
    apply_to = all_review_request_url_names
    js_view_class = 'RB.ShipItActionView'

    def __init__(self, settings):
        super(AdvancedLegacyShipItAction, self).__init__()
        self.settings = settings

    def get_label(self, context):
        user = context['request'].user
        review_request = context['review_request']

        if shipit_forbidden(self.settings, user, review_request):
            return _('Ping It!')

        return ShipItAction.label

    def should_render(self, context):
        request = context['request']
        user = request.user
        return (self.settings.get(CONFIG_ENABLE_LEGACY_BUTTONS) and
                super().should_render(context=context) and
                user.is_authenticated and
                not is_site_read_only_for(user))


class AdvancedLegacyWaitItAction(BaseAction):
    action_id = 'advanced-legacy-wait-it'
    label = _('Wait It!')
    apply_to = all_review_request_url_names
    js_view_class = 'ExtendedApprovalExtension.ActionView'

    def __init__(self, settings):
        super(AdvancedLegacyWaitItAction, self).__init__()
        self.settings = settings

    def should_render(self, context):
        request = context['request']
        user = request.user
        return (self.settings.get(CONFIG_ENABLE_LEGACY_BUTTONS) and
                self.settings.get(CONFIG_ENABLE_WAIT_IT_BUTTON) and
                super().should_render(context=context) and
                user.is_authenticated and
                not is_site_read_only_for(user) and
                not shipit_forbidden(self.settings,
                                     user,
                                     context['review_request']))


class ExtendedApproval(Extension):
    metadata = {
        'Name': 'Extended Approval',
        'Summary': 'Set approval state and show it as dashboard column',
        'Author': 'Andre Klitzing',
        'Author-email': 'aklitzing@gmail.com'
    }
    js_bundles = {
        'default': {
            'source_filenames': (
                'js/extension.js',
            ),
        }
    }

    is_configurable = True
    default_settings = {
        CONFIG_GRACE_PERIOD_DIFFSET: 60,
        CONFIG_GRACE_PERIOD_SHIPIT: 15,
        CONFIG_ENABLE_REVOKE_SHIPITS: False,
        CONFIG_ENABLE_TARGET_SHIPITS: False,
        CONFIG_ENABLE_LEGACY_BUTTONS: False,
        # CONFIG_ENABLE_WAIT_IT_BUTTON: False,
        CONFIG_FORBIDDEN_USER_SHIPITS: '',
        CONFIG_FORBIDDEN_APPROVE_PREFIXES: 'WIP|work in progress',
        CONFIG_FORBIDDEN_APPROVE_PREFIXES_DICT: None,
    }

    def initialize(self):
        ConfigurableApprovalHook(self)

        columns = [ApprovalColumn(self, id='approved')]
        DataGridColumnsHook(self, ReviewRequestDataGrid, columns)
        DashboardColumnsHook(self, columns)
        SignalHook(self, review_request_published, self.on_published)
        SignalHook(self, review_publishing, self.on_review_publishing)
        HideActionHook(self, action_ids=['ship-it'])
        ActionHook(self, actions=[
            AdvancedShipItAction(self.settings),
            AdvancedPingItAction(self.settings),
            AdvancedLegacyEditReviewAction(self.settings),
            AdvancedLegacyAddGeneralCommentAction(self.settings),
            AdvancedLegacyShipItAction(self.settings),
            # AdvancedLegacyWaitItAction(self.settings),
        ])

        prefixDict = {}
        prefixSettings = self.settings.get(CONFIG_FORBIDDEN_APPROVE_PREFIXES)
        for entry in prefixSettings.splitlines():
            lineSplit = entry.split('|', 1)
            prefixDict[lineSplit[0]] = (lineSplit[1]
                                        if len(lineSplit) > 1
                                        else lineSplit[0])
        self.settings[CONFIG_FORBIDDEN_APPROVE_PREFIXES_DICT] = prefixDict

    def shutdown(self):
        super(ExtendedApproval, self).shutdown()

    def _revoke_shipits(self, reviews, request):
        for r in reviews:
            r.revoke_ship_it(request.owner)

    def on_published(self, review_request=None, **kwargs):
        if self.settings.get(CONFIG_ENABLE_REVOKE_SHIPITS):
            if review_request.shipit_count > 0:
                r = ReqReviews(review_request)

                self._revoke_shipits(r.getSelf(), review_request)

                if len(r.getLatest()) == 0:
                    self._revoke_shipits(r.getTotal(), review_request)

    def on_review_publishing(self, user=None, review=None, **kwargs):
        if review.ship_it and shipit_forbidden(self.settings,
                                               review.user,
                                               review.review_request):
            review.ship_it = False
            if review.body_top == review.SHIP_IT_TEXT:
                review.body_top = 'PING! Could someone review and give ShipIt?'
