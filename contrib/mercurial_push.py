#!/usr/bin/env python2
"""A Mercurial hook to post to Review Board on push to a central server.

The hook was designed to make posting to Review Board easy.
It allows user to post to Review Board by using the
ordinary 'hg push', without any need to learn or install RBTools locally.

This hook fits the following workflow:
1. A user makes some (local) commits
2. He pushes those commits to the central server
3. The hook is invoked on the server. The hook checks whether a changeset
   exists and is modified. If it is modified it will be updated. Otherwise
   it will be check if the changeset is approved in previous review
   request. If the changeset does not exist a new request will be created.
4. The hook denies the push if not all commits have been approved.
   It approves the push if the commits have been approved, upon which the
   commits are permanently added to the central repository.
5. Users can then (try to) push the changesets again as often as they wish,
   until some has approved the review request and the push succeeds.

In more detail, the hook does the following:
1. Iterates over all incoming changesets, and tries to find a review request
   with the right commit ID. It uses a hash of the commit date and author
   field. If it cannot find a review request it tries guess the changeset.
2. If you use "hg commit --amend" or "hg rebase" the "date author" hash
   won't be changed.
   If you use "hg histedit" you should be aware that Mercurial will use the
   newest date of the rolled/folded changeset. That will cause to break
   the "date author" hash. So you should be aware that the hook tries to
   guess the changeset by a score of the summary.

   Best practices: Use "hg histedit" to edit a changeset with roll/fold.
   Push the changes and then update your summary or description.


The hook submits review requests using the username of the current user.
You need to configure a "hook" user with the following rights:
 Section: reviews | review request
  - 'Can edit review request'
  - 'Can submit as another user'
  - 'Can change status'
Instead of the rights above you could set the "hook" user as an administrator.


The credentials can be configured through the ~/.reviewboardrc file on server:

REVIEWBOARD_URL: The URL of the Review Board server
USERNAME: The username to use for logging into the server
PASSWORD: The password to use for logging into the server
API_TOKEN: An API token to use for logging into the server. This is
           recommended and replaces the use of PASSWORD.


You need to add the hook to your .hg/hgrc file of your repository.

[hooks]
pretxnchangegroup.rb = /path/to/hook/mercurial_push.py


This hook was tested with "hg serve -d" and Kallithea as a
remote hosting platform and a local repository.

If the hook cannot find rbtools you should check the
environment variable PYTHONPATH.

Example:
   export PYTHONPATH=/usr/lib/python2.7/site-packages


If you want to use rbtools and this hook in a virtualenv you can
setup the hook environment and add a wrapper script.

Setup:
1. virtualenv2 /opt/hook/
2. source /opt/hook/bin/activate
3. pip install rbtools

RBTools 0.7.11 or higher is recommended!

Wrapper:
#!/usr/bin/env python2

import os
import subprocess
import sys

if __name__ == '__main__':
    os.environ['PYTHONPATH'] = '/opt/hook/lib/python2.7/site-packages'
    os.environ['LC_CTYPE'] = 'en_US.UTF-8'
    os.environ['HOOK_HMAC_KEY'] = 'add random stuff here'
    sys.exit(subprocess.call(['/opt/hook/mercurial_push.py'], env=os.environ))



It tries to act like gerrit for git. Every changeset is
a review request that will be amended until it is marked
as "Ship It!".

Look also to reviewboard extension "Extended Approval"
to have better control over the "approved" flag.
"""
from __future__ import unicode_literals

import getpass
import hashlib
import hmac
import json
import os
import re
import six
from functools import partial

from rbtools.clients.mercurial import MercurialClient
from rbtools.commands import Command
from rbtools.hooks.common import HookError
from rbtools.utils.process import execute
from rbtools.utils.users import get_authenticated_session


FAKE_DIFF_TEMPL = b'''diff --git /a /b
new file mode 100644
--- /dev/null
+++ /_____reviewboard_hook_information_____
@@ -0,0 +1,%d @@
+THIS IS A REVIEWBOARD HOOK INFORMATION! THE FOLLOWING CHANGESET
+DOES NOT CONTAIN ANY DIFF. PLEASE REVIEW THE RAW DATA OF THE CHANGESET:
+
+------------------------------------------------------------
%s
+------------------------------------------------------------
'''


def get_ticket_refs(text, prefixes=None):
    """Returns a list of ticket IDs referenced in given text.

    Args:
        prefixes (list of unicode):
            Prefixes allowed before the ticket number.
            For example, prefixes=['app-', ''] would recognize
            both 'app-1' and '1' as ticket IDs.
            By default, prefixes is a regex of '[A-Z-]*'

    Returns:
        set of unicode
        The set of recognized issue numbers.
    """
    verbs = ['closed', 'closes', 'close', 'fixed', 'fixes', 'fix',
             'addresses', 're', 'references', 'refs', 'see',
             'issue', 'bug', 'ticket']

    trigger = '(?:' + '|'.join(verbs) + r')\s*(?:ticket|bug)?:*\s*'
    ticket_join = r'\s*(?:,|and|, and)\s*'

    if prefixes is None:
        safe_prefixes = '[A-Z-]*'
    else:
        safe_prefixes = '|'.join([re.escape(prefix) for prefix in prefixes])

    ticket_id = '#?((?:' + safe_prefixes + r')\d+)'
    matches = re.findall(trigger + ticket_id +
                         ('(?:' + ticket_join + ticket_id + ')?') * 10, text,
                         flags=re.IGNORECASE)
    ids = [submatch for match in matches for submatch in match if submatch]
    return sorted(set(ids))


class MercurialDiffer(object):
    """A class to return diffs compatible with server."""

    class DiffContent(object):
        """A class to hold info about a diff and the diff itself."""
        def __init__(self, request_id, diffset_id,
                     diff, base_commit_id, parent_diff=None):
            envKey = 'HOOK_HMAC_KEY'
            self.key = os.environ.get(envKey)
            if self.key is None:
                raise HookError('You need to define %s' % envKey)

            self._request_id = request_id
            self._diffset_id = diffset_id
            self._base_commit_id = base_commit_id
            self.setDiff(diff)

            if parent_diff is None or len(parent_diff) == 0:
                self._parent_diff = None
            else:
                self._parent_diff = parent_diff

        def getDiff(self):
            return self._diff

        def setDiff(self, diff):
            self._parent_diff = None
            if diff is None or len(diff) == 0:
                self._diff = None
            else:
                self._diff = diff

        def getParentDiff(self):
            return self._parent_diff

        def getBaseCommitId(self):
            return self._base_commit_id

        def getHash(self, diffset_id=None):
            if self._diff is None:
                raise HookError('Cannot get hash of empty diff')

            if diffset_id is None:
                if self._diffset_id is None:
                    raise HookError('Cannot get hash without diffset id')
                diffset_id = self._diffset_id

            if self._request_id is None:
                raise HookError('Cannot get hash without request id')

            hasher = hmac.new(self.key, digestmod=hashlib.sha256)
            hasher.update(str(diffset_id))
            hasher.update(str(self._request_id))
            for line in self._diff.split(b'\n'):
                if (len(line) > 0 and not line.startswith(b'diff') and not
                   line.startswith(b'@@')):
                    hasher.update(line)

            return hasher.hexdigest()

    def __init__(self, root, request_id, diffset_id):
        """Initialize object with the given API root."""
        from rbtools.commands import Command
        self.tool = MercurialClient()
        cmd = Command()
        self.tool.capabilities = cmd.get_capabilities(api_root=root)
        self._request_id = request_id
        self._diffset_id = diffset_id

    def diff(self, rev1, rev2, base):
        """Return a diff and parent diff of given changeset.

        Args:
            rev1 (unicode):
                Last public revision.

            rev2 (unicode):
                Revision of current changeset.

            base (unicode):
                Base revision of current changeset.

        Returns:
            map:
            The diff information of the changeset.
        """
        revisions = {'base': rev1,
                     'tip': rev2,
                     'parent_base': base}
        info = self.tool.diff(revisions=revisions)
        return MercurialDiffer.DiffContent(self._request_id,
                                           self._diffset_id,
                                           info['diff'],
                                           info['base_commit_id'],
                                           info['parent_diff'])


class MercurialReviewRequest(object):
    """A class to represent a review request from a Mercurial hook."""

    def __init__(self, root, repo, changeset, base, submitter):
        """Initialize object with the given information.

        Args:
            root (complex):
                The API root resource.

            repo (int):
                An ID of repository.

            changeset (unicode):
                A revision identifier of changeset.

            base (unicode):
                A revision of parent changeset.

            submitter (unicode):
                The username of current submitter.
        """
        self.root = root
        self.repo = repo
        self.submitter = submitter
        self.changeset = changeset
        self.base = base
        self.summary = self._generate_summary()
        self.description = self._generate_description()
        self.branch = self._generate_branch()
        self.commit_id = self._generate_commit_id()
        self.diff_info = None

        r = self._get_request()
        self.request = r
        self.existing = False if r is None else True
        self.approved = False if r is None else r.approved
        self.failure = None if r is None else r.approval_failure

    def id(self):
        """Return ID of review request.

        Returns:
            int:
            An identifier of review request.

        """
        return None if self.request is None else self.request.id

    def exists(self):
        """Return existence of review request.

        Returns:
            Boolean:
            True if review request exists, otherwise False.
        """
        return self.existing

    def modified(self):
        """Return modified state of review request.

        Returns:
            Boolean:
            True if review request is modified, otherwise False.
        """
        return (self.request.branch != self.branch or
                self.request.summary != self.summary or not
                self._diff_up_to_date())

    def close(self, hgweb=None):
        """Close the given review request with a message."""
        rev = self.changeset
        if hgweb is not None:
            rev = '[{0}]({1}/rev/{0})'.format(rev, hgweb)

        msg = 'Automatically closed by a push (hook): %s' % rev
        self.request.update(status='submitted',
                            close_description=msg,
                            close_description_text_type='markdown')

    def sync(self):
        """Synchronize review request on review board."""
        if self.request is None:
            self.request = self._create()

        if self.diff_info is None:
            self._generate_diff_info()

        self._update()

    def _diff_up_to_date(self):
        """Return modified state of diff.

        Returns:
            Boolean:
            True if diff is up to date, otherwise False.
        """
        if self.diff_info is None:
            self._generate_diff_info()

        if not self.existing:
            return False

        e = self.request.extra_data
        return ('diff_hash' in e and
                self.diff_info.getHash() == e['diff_hash'])

    def _update(self):
        """Update review request draft based on changeset."""
        self.approved = False
        extra_data = None
        draft = self.request.get_or_create_draft(only_fields='',
                                                 only_links='update,'
                                                            'draft_diffs')

        if not self._diff_up_to_date():
            diffs = draft.get_draft_diffs(only_links='upload_diff',
                                          only_fields='')
            d = self.diff_info
            diffs.upload_diff(diff=d.getDiff(),
                              parent_diff=d.getParentDiff(),
                              base_commit_id=d.getBaseCommitId())

            # re-fetch diffset to get id
            diff = draft.get_draft_diffs(only_links='update', only_fields='id')
            extra_data = {'extra_data.diff_hash': d.getHash(diff[0].id)}

        refs = [six.text_type(x)
                for x in get_ticket_refs(self.description)]
        bugs = ','.join(refs)

        draft.update(summary=self.summary,
                     bugs_closed=bugs,
                     description=self.description,
                     description_text_type='markdown',
                     branch=self.branch,
                     commit_id=self.commit_id,
                     public=True)

        if extra_data:
            self.request.update(**extra_data)

    def _create(self):
        """Create a new review request on review board.

        Returns:
            complex:
            The review request object.
        """
        c = self.root.get_review_requests(only_fields='',
                                          only_links='create')
        return c.create(commit_id=self.commit_id,
                        repository=self.repo,
                        submit_as=self.submitter)

    def _generate_diff_info(self):
        """Generate the diff if it has been changed.

        Fake a diff if the diff cannot be created!
        This will happend for the following commands:
        - A commit for new branch: "hg branch" and "hg push --new-branch"
        - A commit to close a branch: "hg commit --close-branch"
        """
        diffset_id = None
        if self.existing:
            latest_diff = self.request.get_latest_diff(only_links='',
                                                       only_fields='id')
            diffset_id = None if latest_diff is None else latest_diff.id

        differ = MercurialDiffer(self.root, self.request.id, diffset_id)
        self.diff_info = differ.diff(self.changeset + '^1',
                                     self.changeset,
                                     self.base)

        if self.diff_info.getDiff() is None:
            detail = 'changeset:   {node}\n' \
                     'branch:      {branch}\n' \
                     'parent:      {p1node}\n' \
                     'parent:      {p2node}\n' \
                     'user:        {author}\n' \
                     'date:        {localdate(date, "UTC")|date}\n' \
                     'extra:       {join(extras, "\n             ")}\n' \
                     'description:\n{desc}\n'
            cmd = ['hg', 'log', '-T', detail, '-r', self.changeset]
            raw_data = execute(cmd,
                               results_unicode=False).strip().split(b'\n')
            content = []
            for data in raw_data:
                content.append(b'+%s' % data)

            fake_diff = FAKE_DIFF_TEMPL % (len(raw_data) + 5,
                                           b'\n'.join(content))
            self.diff_info.setDiff(fake_diff)

    def _generate_branch(self):
        """Return the branch name of a changeset revision.

        Returns:
            unicode:
            The revision identifier.
        """
        cmd = ['hg', 'id', '--branch', '-r', self.changeset]
        return execute(cmd).strip()

    def _generate_summary(self):
        """Return a summary of a changeset revision.

        Returns:
            unicode:
            The summary line of changeset.
        """
        cmd = ['hg', 'log', '-r', self.changeset,
               '--template', '{desc|firstline}']
        return execute(cmd).strip()

    def _generate_description(self):
        """Return a description of a changeset revision.

        Returns:
            unicode:
            The description of changeset.
        """
        cmd = ['hg', 'log', '-r', self.changeset,
               '--template',
               '{author} ({date|isodate}) [{node|short}] [{branch}]:'
               '\n{desc}\n\n']
        return execute(cmd)

    def _generate_commit_id(self):
        """Return a commit id of the changeset.

        Returns:
            unicode:
            A generated commit id  of changeset.
        """
        author_date = execute(['hg', 'log', '-r', self.changeset,
                               '--template', '{author} {date}'],
                              results_unicode=False).strip()

        hasher = hashlib.md5()
        hasher.update(author_date)
        hasher.update(str(self.repo))
        return hasher.hexdigest()

    def _get_request(self):
        """Find a review request in the given repo for the given changeset.

        Returns:
            complex:
            The corresponding review request on review board if exist,
            otherwise None.
        """
        fields = ('summary,approved,approval_failure,id,commit_id,'
                  'branch,description,extra_data')
        links = 'submitter,reviews,update,diffs,latest_diff,draft,self'

        reqs = self.root.get_review_requests(repository=self.repo,
                                             status='pending',
                                             show_all_unpublished=True,
                                             only_fields=fields,
                                             only_links=links,
                                             commit_id=self.commit_id)

        count = len(reqs)
        if count == 0:
            reqs = self.root.get_review_requests(repository=self.repo,
                                                 status='pending',
                                                 show_all_unpublished=True,
                                                 only_fields=fields,
                                                 only_links=links,
                                                 from_user=self.submitter)
            found = None
            for r in reqs:
                if r.summary == self.summary:
                    if found is not None:
                        raise HookError('Multiple review requests: %s'
                                        % self.summary)
                    found = r

            return found

        elif count == 1:
            r = reqs[0]
            if r.links.submitter.title != self.submitter:
                raise HookError('Owner of review request (%d): %s'
                                % (r.id, r.links.submitter.title))
            return r

        return None


class MercurialHookCmd(Command):
    """Helper to parse configuration from .reviewboardrc file."""

    name = 'MercurialHook'
    option_list = [
        Command.server_options,
    ]

    def __init__(self):
        parser = self.create_arg_parser([])
        self.options = parser.parse_args([])


class MercurialHook(object):
    """Class to represent a hook for Mercurial repositories."""

    def __init__(self, log, repo):
        self.log = log
        self.submitter = None
        self.repo_name = None
        self.repo_id = None
        self.root = None
        self.hgweb = None

        if 'KALLITHEA_EXTRAS' in os.environ:
            kallithea = json.loads(os.environ['KALLITHEA_EXTRAS'])
            self.repo_name = kallithea['repository']
            if 'default' in kallithea['username']:
                self.log('Anonymous access is not supported')
            else:
                self.submitter = kallithea['username']
        elif 'REPO_NAME' in os.environ and 'REMOTE_USER' in os.environ:
                self.submitter = os.environ['REMOTE_USER']
                self.repo_name = os.environ['REPO_NAME']
        else:
            self.submitter = getpass.getuser()
            self.repo_name = repo

        self.log('Push as user "%s" to "%s"...',
                 self.submitter, self.repo_name)

    def _set_repo_id(self):
        """Set ID of repository."""
        fields = 'path,mirror_path,id'

        repos = self.root.get_repositories(name=self.repo_name,
                                           tool='Mercurial',
                                           only_fields=fields,
                                           only_links='')

        if repos.num_items < 1:
            repos = self.root.get_repositories(path=self.repo_name,
                                               tool='Mercurial',
                                               only_fields=fields,
                                               only_links='')
            if repos.num_items < 1:
                raise HookError('Could not open Review Board repository:'
                                '\n%s\n'
                                'Do you have the permissions to access this '
                                'repository?' % self.repo_name)

        r = repos[0]
        self.repo_id = r.id
        for path in [r.path, r.mirror_path]:
            if path.startswith('http'):
                self.hgweb = path.rstrip('/')
                break

    def _set_root(self):
        """Set API root object."""
        cmd = MercurialHookCmd()
        server_url = cmd.get_server_url(None, None)
        api_client, self.root = cmd.get_api(server_url)
        session = get_authenticated_session(api_client, self.root,
                                            auth_required=True, num_retries=0)
        if session is None or not session.authenticated:
            raise HookError('Please add an USERNAME and a PASSWORD or '
                            'API_TOKEN to .reviewboardrc')

    def _list_of_incoming(self, node):
        """Return a list of all changeset hexes after (and including) node.

        Assumes that all incoming changeset have subsequent revision numbers.

        Returns:
            list of unicode:
            The list of revision identifiers.
        """
        lines = execute(['hg', 'log', '-r', node + ':',
                         '--template', '{node|short}\n'])

        return lines.split('\n')[:-1]

    def _check_duplicate(self, request, revreqs):
        """Check if a summary is already used during this push.

        Args:
            request (rbtools.hooks.mercurial.MercurialReviewRequest):
                A review request object.

            revreqs (list of rbtools.hooks.mercurial.MercurialReviewRequest):
                All previous review requests.

        Returns:
            Boolean:
            True if summary is duplicated, otherwise False.
        """
        return any(
            r.summary == request.summary
            for r in revreqs
        )

    def _handle_changeset_list(self, node):
        """Process all incoming changesets.

        Args:
            node (unicode):
                The hex of the first changeset.

        Returns:
            int:
            0 on success, otherwise non-zero.
        """
        changesets = self._list_of_incoming(node)
        base = node + '^1'
        revreqs = []
        self.log('Processing %d changeset(s)...', len(changesets))

        for changeset in changesets:
            request = MercurialReviewRequest(self.root,
                                             self.repo_id,
                                             changeset,
                                             base,
                                             self.submitter)

            if self._check_duplicate(request, revreqs):
                self.log('Ignoring changeset (%s) as it has a '
                         'duplicated summary: %s',
                         request.changeset, request.summary)
                continue

            self._handle_review_request(request)
            revreqs.append(request)

        return self._handle_approved_review_requests(revreqs)

    def _handle_approved_review_requests(self, revreqs):
        """Handle approved review requests.

        Args:
            revreqs (list of rbtools.hooks.mercurial.MercurialReviewRequest):
                All processed review requests.

        Returns:
            int:
            0 on success, otherwise non-zero.
        """
        idx = None

        for i, r in enumerate(revreqs):
            if not r.approved:
                idx = i
                break

        if idx is None:
            for r in revreqs:
                self.log('Closing review request: %s', r.id())
                r.close(self.hgweb)
            return 0
        elif idx > 0:
            self.log('If you want to push the already approved ')
            self.log('changes, you can (probably) execute this:')
            self.log('hg push -r %s', revreqs[idx - 1].changeset)

        return 1

    def _handle_review_request(self, request):
        """Handle given review request.

        Args:
            request (rbtools.hooks.mercurial.MercurialReviewRequest):
                A review request object.
        """
        if request.exists():
            if request.modified():
                request.sync()
                self.log('Updated review request (%d) for '
                         'changeset: %s', request.id(), request.changeset)
            else:
                if request.approved:
                    self.log('Found approved review request (%d) for '
                             'changeset: %s', request.id(),
                             request.changeset)
                else:
                    self.log('Found unchanged review request (%d) for '
                             'changeset: %s | %s', request.id(),
                             request.changeset, request.failure)
        else:
            request.sync()
            self.log('Created review request (%d) for '
                     'changeset: %s', request.id(), request.changeset)

    def push_to_reviewboard(self, node):
        """Run the hook.

        Args:
            node (unicode):
                The hex of the first changeset.

        Returns:
            int:
            Return code of execution. 0 on success, otherwise non-zero.
        """
        if len(node) == 0:
            raise HookError('Initial changeset is undefined.')

        if self.submitter is None or self.repo_name is None:
            raise HookError('Cannot detect submitter or repository.')

        self._set_root()
        self._set_repo_id()
        return self._handle_changeset_list(node)


if __name__ == '__main__':
    import sys
    import logging

    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=logging.INFO)
    logger = logging.getLogger('reviewboardhook')

    try:
        h = MercurialHook(partial(logger.info), os.environ['HG_PENDING'])
        sys.exit(h.push_to_reviewboard(os.environ['HG_NODE']))
    except Exception as e:
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.exception('Backtrace of error: %s' % e)
        else:
            for line in six.text_type(e).split('\n'):
                logger.error(line)

    sys.exit(-1)
