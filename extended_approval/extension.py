from __future__ import unicode_literals

import pytz
from datetime import datetime, timedelta

from djblets.datagrid.grids import Column

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
            detailed_label='Approved',
            db_field='shipit_count',
            sortable=True,
            shrink=True,
            *args, **kwargs)

        self.settings = extension.settings

    def _render_data_shipit(self, style, count):
        return '<span class="shipit-count" %s>' \
               ' <div class="rb-icon rb-icon-shipit-checkmark"' \
               '      title="%s"></div> %s' \
               '</span>' % \
               (style, self.image_alt, count)

    def render_data(self, state, review_request):
        """Return the rendered contents of the column."""
        if review_request.issue_open_count > 0:
            return ('<span class="issue-count">'
                    ' <span class="issue-icon">!</span> %s'
                    '</span>'
                    % review_request.issue_open_count)

        if review_request.summary.startswith('WIP'):
            return ('<span class="issue-count" style="background-image: '
                    'linear-gradient(#FF0000, #DD0000)">WIP</span>')

        total_shipits, latest_shipits, diffset = get_ship_its(review_request)
        if len(total_shipits) == 0:
            return ''
        elif len(latest_shipits) == 0:
            style = ('style="background-image: '
                     'linear-gradient(#ffc04d, #ffc04a)"')
        elif check_grace_period(self.settings, diffset,
                                latest_shipits[0]) is not None:
            style = ('style="background-image: '
                     'linear-gradient(#449900, #44aa00)"')
        else:
            style = ''

        return self._render_data_shipit(style, len(latest_shipits))


class ConfigurableApprovalHook(ReviewRequestApprovalHook):
    def __init__(self, extension, *args, **kwargs):
        super(ConfigurableApprovalHook, self).__init__(
            extension, *args, **kwargs)
        self.settings = extension.settings

    def is_approved(self, review_request, prev_approved, prev_failure):
        if review_request.issue_open_count > 0:
            return False, 'The review request has open issus'

        if review_request.summary.startswith('WIP'):
            return False, 'The review request is marked as "work in progress"'

        if not prev_approved:
            return False, prev_failure

        total_shipits, latest_shipits, diffset = get_ship_its(review_request)
        if len(latest_shipits) == 0:
            return False, 'The latest diff has not been marked "Ship It!"'

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

        columns = [ApprovalColumn(self, id='approved', label='Approved')]
        DataGridColumnsHook(self, ReviewRequestDataGrid, columns)
        DashboardColumnsHook(self, columns)
