from __future__ import unicode_literals

import pytz
from datetime import datetime, timedelta

from reviewboard.reviews.actions import get_top_level_actions
from reviewboard.reviews.default_actions import (ShipItAction,
                                                 get_default_actions)

from djblets.datagrid.grids import Column

from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _

from reviewboard.extensions.base import Extension
from reviewboard.extensions.hooks import (DataGridColumnsHook,
                                          DashboardColumnsHook,
                                          ReviewRequestApprovalHook,
                                          SignalHook)
from reviewboard.datagrids.grids import ReviewRequestDataGrid
from reviewboard.reviews.signals import (review_publishing,
                                         review_request_published)


CONFIG_GRACE_PERIOD_DIFFSET = 'grace_period_diffset'
CONFIG_GRACE_PERIOD_SHIPIT = 'grace_period_shipit'
CONFIG_ENABLE_REVOKE_SHIPITS = 'enable_revoke_shipits'


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
        if review_request.summary.startswith('WIP'):
            return self._render([{
                      'icon_name': 'issue-dropped',
                      'title': _('WIP'),
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

        if review_request.summary.startswith('WIP'):
            return False, 'The review request is marked as "work in progress"'

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
    def get_label(self, context):
        if context['request'].user == context['review_request'].owner:
            return _('Ping It!')

        return ShipItAction.label


class ExtendedApproval(Extension):
    metadata = {
        'Name': 'Extended Approval',
        'Summary': 'Set approval state and show it as dashboard column',
        'Author': 'Andre Klitzing',
        'Author-email': 'aklitzing@gmail.com'
    }

    is_configurable = True
    default_settings = {
        CONFIG_GRACE_PERIOD_DIFFSET: 60,
        CONFIG_GRACE_PERIOD_SHIPIT: 15,
        CONFIG_ENABLE_REVOKE_SHIPITS: False,
    }

    def initialize(self):
        ConfigurableApprovalHook(self)

        columns = [ApprovalColumn(self, id='approved')]
        DataGridColumnsHook(self, ReviewRequestDataGrid, columns)
        DashboardColumnsHook(self, columns)
        SignalHook(self, review_request_published, self.on_published)
        SignalHook(self, review_publishing, self.on_review_publishing)

        self._replace_action(AdvancedShipItAction)

    def shutdown(self):
        super(ExtendedApproval, self).shutdown()
        self._replace_action(ShipItAction)

    def _replace_action(self, action):
        top_actions = []
        for x in get_top_level_actions():
            top_actions.append(x)

        for x in top_actions:
            x.unregister()

        new_actions = []
        for x in get_default_actions():
            if x.action_id == action.action_id:
                new_actions.append(action())
            else:
                new_actions.append(x)

        for x in reversed(new_actions):
            x.register()

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
        if review.ship_it and review.user == review.review_request.owner:
            review.ship_it = False
            if review.body_top == review.SHIP_IT_TEXT:
                review.body_top = 'PING! Could someone review and give ShipIt?'
