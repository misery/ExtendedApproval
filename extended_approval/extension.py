from __future__ import unicode_literals

import pytz
from datetime import datetime, timedelta

from djblets.datagrid.grids import Column

from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _

from reviewboard.extensions.base import Extension
from reviewboard.extensions.hooks import (DataGridColumnsHook,
                                          DashboardColumnsHook,
                                          ReviewRequestApprovalHook)
from reviewboard.datagrids.grids import ReviewRequestDataGrid


CONFIG_GRACE_PERIOD_DIFFSET = 'grace_period_diffset'
CONFIG_GRACE_PERIOD_SHIPIT = 'grace_period_shipit'


def get_ship_its(review_request):
    latest_diffset = review_request.get_latest_diffset()
    total_shipits = []
    latest_shipits = []

    if latest_diffset:
        shipit_reviews = review_request.reviews.filter(ship_it=True)

        for shipit in shipit_reviews:
            if review_request.submitter != shipit.user:
                if shipit.user not in (u.user for u in total_shipits):
                    total_shipits.append(shipit)

                if shipit.timestamp > latest_diffset.timestamp:
                    if shipit.user not in (u.user for u in latest_shipits):
                        latest_shipits.append(shipit)

    return (total_shipits, latest_shipits, latest_diffset)


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

        total_shipits, latest_shipits, diffset = get_ship_its(review_request)
        if len(total_shipits) > 0:
            if len(latest_shipits) > 0:
                period = check_grace_period(self.settings, diffset,
                                            latest_shipits[0])

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

        total_shipits, latest_shipits, diffset = get_ship_its(review_request)
        if len(latest_shipits) == 0:
            return False, 'The latest diff has not been marked' \
                          ' "Ship It!" by someone else'

        period = check_grace_period(self.settings, diffset, latest_shipits[0])
        if period is not None:
            return False, period

        return True


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
    }

    def initialize(self):
        ConfigurableApprovalHook(self)

        columns = [ApprovalColumn(self, id='approved')]
        DataGridColumnsHook(self, ReviewRequestDataGrid, columns)
        DashboardColumnsHook(self, columns)
