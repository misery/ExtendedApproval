from __future__ import unicode_literals

from djblets.datagrid.grids import Column

from reviewboard.extensions.base import Extension
from reviewboard.extensions.hooks import (DataGridColumnsHook,
                                          DashboardColumnsHook,
                                          ReviewRequestApprovalHook)
from reviewboard.datagrids.grids import ReviewRequestDataGrid


def get_shipit_counts(review_request):
    latest_diffset = review_request.get_latest_diffset()
    latest_shipits = 0
    total_shipits = 0

    shipit_reviews = review_request.reviews.filter(ship_it=True)
    if latest_diffset:
        for shipit in shipit_reviews:
            if review_request.submitter != shipit.user:
                total_shipits += 1
                if shipit.timestamp > latest_diffset.timestamp:
                    latest_shipits += 1

    return (total_shipits, latest_shipits)


class ApprovalColumn(Column):
    """Shows the approved state for a review request."""
    def __init__(self, *args, **kwargs):
        """Initialize the column."""
        super(ApprovalColumn, self).__init__(
            detailed_label='Approved',
            db_field='shipit_count',
            sortable=True,
            shrink=True,
            *args, **kwargs)

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

        total_shipits, latest_shipits = get_shipit_counts(review_request)
        if total_shipits == 0:
            return ''
        elif latest_shipits == 0:
            style = ('style="background-image: '
                     'linear-gradient(#ffc04d, #ffc04a)"')
        else:
            style = ''

        return '<span class="shipit-count" %s>' \
               ' <div class="rb-icon rb-icon-shipit-checkmark"' \
               '      title="%s"></div> %s' \
               '</span>' % \
               (style, self.image_alt, latest_shipits)


class ConfigurableApprovalHook(ReviewRequestApprovalHook):
    def is_approved(self, review_request, prev_approved, prev_failure):
        if review_request.issue_open_count > 0:
            return False, 'The review request has open issus'

        if review_request.summary.startswith('WIP'):
            return False, 'The review request is marked as "work in progress"'

        if not prev_approved:
            return False, prev_failure

        total_shipits, latest_shipits = get_shipit_counts(review_request)
        if latest_shipits == 0:
            return False, 'The latest diff has not been marked "Ship It!"'

        return True


class ExtendedApproval(Extension):
    metadata = {
        'Name': 'Extended Approval',
        'Summary': 'Set approval state and show it as dashboard column',
        'Author': 'Andre Klitzing',
        'Author-email': 'aklitzing@gmail.com'
    }

    is_configurable = False

    def initialize(self):
        ConfigurableApprovalHook(self)

        columns = [ApprovalColumn(id='approved', label='Approved')]
        DataGridColumnsHook(self, ReviewRequestDataGrid, columns)
        DashboardColumnsHook(self, columns)
