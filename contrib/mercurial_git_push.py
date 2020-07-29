#!/usr/bin/env python
"""A Mercurial/git hook to post to Review Board on push to a central server.

The hook was designed to make posting to Review Board easy.
It allows user to post to Review Board by using the
ordinary 'hg push', without any need to learn or install RBTools locally.

This hook fits the following workflow:
1. A user makes some (local) commits.
2. He pushes those commits to the central server.
3. The hook is invoked on the server. The hook checks whether a changeset
   exists and is modified. If it is modified it will be updated. Otherwise
   it will check if the changeset is approved in that review request.
   If the changeset does not exist a new request will be created.
4. The hook denies the push if not all commits have been approved.
   It approves the push if all commits have been approved, upon which the
   commits are permanently added to the central repository.
5. Users can then (try to) push the changesets again as often as they wish,
   until some has approved the review request and the push succeeds.

In more detail, the hook does the following:
1. Iterates over all incoming changesets, and tries to find a review request
   with the right commit ID. It uses a hash of the commit date and author
   field. If it cannot find a review request it tries to guess the changeset.
2. If you use "hg commit --amend" or "hg rebase" the "date author" hash
   won't be changed.
   If you use "hg histedit" you should be aware that Mercurial < 4.2 will
   use the newest date of the rolled/folded changeset. That will cause to break
   the "date author" hash. So you should be aware that the hook tries to
   guess the changeset by the summary.

   Best practices: Use "hg histedit" on Mercurial < 4.2 to edit a changeset
   with roll/fold.
   Push the changes and then update your summary or description.


The hook submits review requests using the username of the current user.
You need to configure a "hook" user with the following rights:
 Section: reviews | review request
  - 'Can edit review request'
  - 'Can submit as another user'
  - 'Can change status'
Instead of the rights above you could set the "hook" user as an administrator.


The credentials can be configured through
the .reviewboardrc file (see RBTOOLS_CONFIG_PATH) on server:

REVIEWBOARD_URL: The URL of the Review Board server
USERNAME: The username to use for logging into the server
PASSWORD: The password to use for logging into the server
API_TOKEN: An API token to use for logging into the server. This is
           recommended and replaces the use of PASSWORD.


## Mercurial
You need to add the hook to your .hg/hgrc file of your repository.
Use "/etc/gitlab/heptapod.hgrc" as the system-wide config for Heptapod.

[hooks]
pretxnchangegroup.rb = /path/to/hook/mercurial_push.py

This hook was tested with "hg serve", Heptapod, Kallithea and SCM-Manager
as a remote hosting platform and a local repository.

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

RBTools 1.0.2 or higher is recommended!

Wrapper:
#!/usr/bin/env python2

import os
import subprocess
import sys

if __name__ == '__main__':
    os.environ['PYTHONPATH'] = '/opt/hook/lib/python2.7/site-packages'
    os.environ['LC_CTYPE'] = 'en_US.UTF-8'
    os.environ['HOOK_HMAC_KEY'] = 'add random to override /etc/machine-id'
    os.environ['RBTOOLS_CONFIG_PATH'] = '/opt/hook'
    sys.exit(subprocess.call(['/opt/hook/mercurial_push.py'], env=os.environ))



It tries to act like gerrit for git. Every changeset is
a review request that will be amended until it is marked
as "Ship It!".

Look also to reviewboard extension "Extended Approval"
to have better control over the "approved" flag.
"""
from __future__ import unicode_literals

import datetime as dt
import getpass
import hashlib
import hmac
import json
import os
import re
import six
import sys
from functools import partial

from rbtools import __version__ as rbversion
from rbtools.clients.git import GitClient
from rbtools.clients.mercurial import MercurialClient
from rbtools.commands import Command
from rbtools.hooks.common import HookError
from rbtools.utils.process import execute
from rbtools.utils.users import get_authenticated_session

MAX_MERGE_ENTRIES = 30

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


class BaseDiffer(object):
    """A class to return diffs compatible with server."""

    class DiffContent(object):
        """A class to hold info about a diff and the diff itself."""
        def __init__(self, request_id,
                     diff, base_commit_id, parent_diff=None):
            envKey = 'HOOK_HMAC_KEY'
            self.key = os.environ.get(envKey)
            if self.key is None:
                try:
                    with open('/etc/machine-id', 'r') as content_file:
                        self.key = content_file.read().strip()
                except Exception:
                    raise HookError('You need to define %s' % envKey)

            self._request_id = request_id
            self._base_commit_id = base_commit_id
            self.setDiff(diff)

            if parent_diff is None or len(parent_diff) == 0:
                self._parent_diff = None
            else:
                self._parent_diff = parent_diff

        def getDiff(self):
            return self._diff

        def setDiff(self, diff):
            self._hashes = {}
            self._parent_diff = None
            if diff is None or len(diff) == 0:
                self._diff = None
            else:
                self._diff = diff

        def getParentDiff(self):
            return self._parent_diff

        def getBaseCommitId(self):
            return self._base_commit_id

        def _getHasher(self):
            if self._request_id is None:
                raise HookError('Cannot get hash without request id')

            if six.PY2:
                k = self.key
            else:
                k = bytes(self.key, 'ascii')

            hasher = hmac.new(k, digestmod=hashlib.sha256)
            hasher.update(six.text_type(self._request_id).encode('utf-8'))
            return hasher

        def getRawHash(self, content):
            if content is None:
                raise HookError('Cannot get hash of empty content')

            hasher = self._getHasher()
            hasher.update(content)
            return hasher.hexdigest()

        def getHash(self, diffset_id):
            if self._diff is None:
                raise HookError('Cannot get hash of empty diff')

            if diffset_id is None:
                raise HookError('Cannot get hash without diffset id')

            if diffset_id in self._hashes:
                return self._hashes[diffset_id]

            hasher = self._getHasher()
            hasher.update(six.text_type(diffset_id).encode('utf-8'))
            for line in self._diff.splitlines():
                if (len(line) > 0 and not line.startswith(b'diff') and not
                   line.startswith(b'@@')) and not line.startswith(b'#'):
                    hasher.update(line)

            h = hasher.hexdigest()
            self._hashes[diffset_id] = h
            return h

    def __init__(self, root, request_id):
        """Initialize object with the given API root."""
        self.tool = None
        self._request_id = request_id

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
        return BaseDiffer.DiffContent(self._request_id,
                                      info['diff'],
                                      info['base_commit_id'],
                                      info['parent_diff'])


class MercurialDiffer(BaseDiffer):
    def __init__(self, root, request_id):
        super(MercurialDiffer, self).__init__(root, request_id)
        self.tool = MercurialClient()
        cmd = Command()
        self.tool.capabilities = cmd.get_capabilities(api_root=root)


class GitDiffer(BaseDiffer):
    def __init__(self, root, request_id):
        super(GitDiffer, self).__init__(root, request_id)
        self.tool = GitClient()
        self.tool.get_repository_info()


class BaseReviewRequest(object):
    """A class to represent a review request from a Mercurial hook."""

    def __init__(self, root, repo, changeset, base, submitter):
        """Initialize object with the given information.

        Args:
            root (complex):
                The API root resource.

            repo (int):
                An ID of repository.

            changeset (object of MercurialRevision):
                An object of MercurialRevision.

            base (unicode):
                A revision of parent changeset.

            submitter (unicode):
                The username of current submitter.
        """
        self.root = root
        self.repo = repo
        self.submitter = submitter
        self._changeset = changeset
        self.base = base
        self.commit_id = self._generate_commit_id()
        self.diff_info = None
        self._skippable = None

        regex = os.environ.get('HOOK_FILE_UPLOAD_REGEX')
        if not regex:
            regex = r'.*\.(png|jpg|jpeg|gif|svg|webp|ico|bmp)$'
        self.regexUpload = re.compile(regex)

        r = self._get_request()
        self.request = r
        self.existing = False if r is None else True
        self.failure = None if r is None else r.approval_failure
        self.approved = False if r is None or self.skippable() else r.approved

        self.diffset_id = None
        if r is not None and 'latest_diff' in r.links:
            self.diffset_id = r.get_latest_diff(only_links='',
                                                only_fields='id').id

    def id(self):
        """Return ID of review request.

        Returns:
            int:
            An identifier of review request.

        """
        return None if self.request is None else self.request.id

    def node(self, short=True):
        """Return changeset as hex node."""
        return self._changeset.node(short)

    def branch(self):
        """Return branch of changeset."""
        return self._changeset.branch()

    def summary(self):
        return self._changeset.summary()

    def skippable(self):
        if self._skippable is None:
            regex = r'Reviewed at https://'

            if self.summary().startswith('SKIP'):
                self._skippable = True
                self.failure = 'Starts with SKIP'
            elif re.search(regex, self._changeset.desc()):
                self._skippable = True
                self.failure = 'Description contains: "%s"' % regex
            else:
                self._skippable = False

        return self._skippable

    def _info(self):
        return self._changeset.info()

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
        return (self.request.branch != self.branch() or
                self.request.summary != self.summary() or
                self._modified_description() or not
                self._diff_up_to_date())

    def close(self, hgweb=None):
        """Close the given review request with a message."""
        rev = self.node()
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

        if not self.existing or self.diffset_id is None:
            return False

        e = self.request.extra_data
        return ('diff_hash' in e and
                self.diff_info.getHash(self.diffset_id) == e['diff_hash'])

    def _update_attachments(self):
        stored_hashes = {}
        if 'file_hashes' in self.request.extra_data:
            stored_hashes = json.loads(self.request.extra_data['file_hashes'])

        a = self.request.get_file_attachments(only_fields='caption,'
                                              'attachment_history_id',
                                              only_links='delete')
        hashes = {}
        existing = {}
        for entry in a:
            existing[entry['caption']] = entry

        def modified(filename):
            d = self._changeset.diffstat()
            return filename in d and d[filename] != '0'

        def handle_upload(f):
            e = existing.get(f)
            history = e['attachment_history_id'] if e else None
            content = self._changeset.file(f)
            hashes[f] = self.diff_info.getRawHash(content)
            if f not in stored_hashes or hashes[f] != stored_hashes[f]:
                a.upload_attachment(f, content, f, history)

        mods = self._changeset.files('{file_mods|json}')
        adds = self._changeset.files('{file_adds|json}')
        foundAttachments = []
        for entry in set(adds + mods):
            if self.regexUpload.match(entry):
                foundAttachments.append(entry)

        if len(foundAttachments) > 0:
            files = self._changeset.files()  # let's detect deleted files
            copies = self._changeset.files('{file_copies|json}')
            for e in foundAttachments:
                if e not in files:
                    continue
                if e in copies and not modified(e):
                    continue
                handle_upload(e)

        for entry in stored_hashes:
            if entry not in hashes:
                existing.get(entry).delete()

        return json.dumps(hashes)

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
            diff = draft.get_draft_diffs(only_links='', only_fields='id')
            extra_data = {'extra_data.diff_hash': d.getHash(diff[0].id)}
            if rbversion >= '1.0.3':
                extra_data['extra_data.file_hashes'] = \
                                                     self._update_attachments()

        refs = [six.text_type(x)
                for x in get_ticket_refs(self._changeset.desc())]
        bugs = ','.join(refs)

        draft.update(summary=self.summary(),
                     bugs_closed=bugs,
                     description=self._info(),
                     description_text_type='markdown',
                     branch=self.branch(),
                     commit_id=self.commit_id,
                     publish_as_owner=True,
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

    def _modified_description(self):
        """Filter changeset information and check if the
           description got changed.
        """
        regex = (r'\([0-9]{4}-[0-9]{2}-[0-9]{2} '
                 r'[0-9]{2}:[0-9]{2}:[0-9]{2}'
                 r'[\s]{0,1}[+-][0-9]{2}[:]{0,1}[0-9]{2}\) '
                 r'\[[0-9|a-z]+\]')
        regex = re.compile(regex)

        old = self.request.description
        new = self._info()
        return regex.sub('', old, 1) != regex.sub('', new, 1)

    def _generate_commit_id(self):
        """Return a commit id of the changeset.

        Returns:
            unicode:
            A generated commit id of changeset.
        """
        hasher = hashlib.md5()
        hasher.update(self._changeset.author().encode('utf-8'))
        hasher.update(self._changeset.date().encode('utf-8'))
        hasher.update(six.text_type(self.repo).encode('utf-8'))
        s = self.summary()
        if (s.startswith('[maven-release-plugin]') or
                s.startswith('Added tag ') or
                s.startswith('Moved tag ') or
                s.startswith('Removed tag ')):
            hasher.update(s)
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
        links = 'submitter,update,latest_diff,draft,file_attachments'

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
                if r.summary == self.summary():
                    if found is not None:
                        raise HookError('Multiple review requests: %s'
                                        % self.summary())
                    found = r

            return found

        elif count == 1:
            r = reqs[0]
            if r.links.submitter.title.lower() != self.submitter.lower():
                raise HookError('Owner of review request (%d): %s'
                                % (r.id, r.links.submitter.title))
            return r

        return None


class MercurialReviewRequest(BaseReviewRequest):
    def __init__(self, root, repo, changeset, base, submitter):
        super(MercurialReviewRequest, self).__init__(root,
                                                     repo,
                                                     changeset,
                                                     base,
                                                     submitter)

    def _generate_diff_info(self):
        """Generate the diff if it has been changed.

        Fake a diff if the diff cannot be created!
        This will happend for the following commands:
        - A commit for new branch: "hg branch" and "hg push --new-branch"
        - A commit to close a branch: "hg commit --close-branch"
        """
        differ = MercurialDiffer(self.root, self.request.id)
        parent = MercurialRevision.normalize(self.node() + '^1')
        self.diff_info = differ.diff(parent,
                                     self.node(),
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
            cmd = ['hg', 'log', '-T', detail, '-r', self.node()]
            raw_data = execute(cmd,
                               results_unicode=False).strip().splitlines()
            content = []
            for data in raw_data:
                content.append(b'+%s' % data)

            fake_diff = FAKE_DIFF_TEMPL % (len(raw_data) + 5,
                                           b'\n'.join(content))
            self.diff_info.setDiff(fake_diff)


class GitReviewRequest(BaseReviewRequest):
    def __init__(self, root, repo, changeset, base, submitter):
        super(GitReviewRequest, self).__init__(root,
                                               repo,
                                               changeset,
                                               base,
                                               submitter)

    def _generate_diff_info(self):
        """Generate the diff if it has been changed."""

        # git hash-object -t tree /dev/null
        initialCommit = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'

        if self.base == '0000000000000000000000000000000000000000':
            base = initialCommit
        else:
            base = self.base

        if len(self._changeset.parent()) > 0:
            parent = self.node() + '^1'
        else:
            parent = initialCommit

        differ = GitDiffer(self.root, self.request.id)
        self.diff_info = differ.diff(parent,
                                     self.node(),
                                     base)


class MercurialGitHookCmd(Command):
    """Helper to parse configuration from .reviewboardrc file."""

    name = 'MercurialGitHook'
    option_list = [
        Command.server_options,
    ]

    def __init__(self):
        parser = self.create_arg_parser([])
        self.options = parser.parse_args([])


class BaseRevision(object):
    def __init__(self):
        self._summary = None
        self._info = None

    def summary(self):
        if self._summary is None:
            self._summary = self.desc().splitlines()[0].strip()
            if len(self._summary) > 150:
                self._summary = self._summary[0:150] + ' ...'
        return self._summary

    def info(self):
        if self._info is None:
            template = '{author} ({date}) [{node}] [{branch}]:\n{desc}'
            self._info = template.format(author=self.author(),
                                         date=self.date(),
                                         node=self.node(),
                                         branch=self.branch(),
                                         desc=self.desc())
            merges = self.merges()
            if merges:
                self._info += '\n\n\n'

                files = self.files()
                self._info += '# Touched %d file(s) by this merge ' \
                              'changeset\n' % len(files)
                for entry in files:
                    self._info += '+ ' + entry + '\n'

                self._info += '# Merges %d changeset(s)\n' % len(merges)

                def add(changes):
                    t = '+ [{node}] {summary}\n'
                    for rev in changes:
                        self._info += t.format(node=rev.node(),
                                               summary=rev.summary())

                if len(merges) > MAX_MERGE_ENTRIES + 1:
                    add(merges[0:MAX_MERGE_ENTRIES])
                    self._info += '+ ...\n'
                    add([merges[-1]])
                else:
                    add(merges)

            self._info = self._info.strip()

        return self._info


class MercurialRevision(BaseRevision):
    """Class to represent information of changeset."""
    @staticmethod
    def fetch(revset):
        changes = execute(['hg', 'log', '-r', revset,
                           '--template', 'json'])
        result = []
        for entry in json.loads(changes):
            result.append(MercurialRevision(entry))
        return result

    @staticmethod
    def normalize(node):
        return execute(['hg', 'log', '-r', node, '-T {node}'])

    def __init__(self, json):
        super(MercurialRevision, self).__init__()
        self.json = json
        self._date = None
        self._merges = None
        self._diffstat = None

    def node(self, short=True):
        n = self.json['node']
        return n[:12] if short else n

    def branch(self):
        return self.json['branch']

    def author(self):
        return self.json['user']

    def date(self):
        if self._date is None:
            class Offset(dt.tzinfo):
                def __init__(self, offset):
                    self._offset = dt.timedelta(seconds=offset)

                def utcoffset(self, dt):
                    return self._offset

            d = self.json['date']
            offset = d[1] * -1
            d = dt.datetime.utcfromtimestamp(d[0] + offset)
            d = d.replace(tzinfo=Offset(offset))
            self._date = d.isoformat(str(' '))

        return self._date

    def desc(self):
        return self.json['desc']

    def diffstat(self):
        if self._diffstat is None:
            self._diffstat = {}
            o = execute(['hg', 'diff', '-g',
                         '--stat', '-c', self.node()]).splitlines()
            del o[-1]  # useless summary line
            for entry in o:
                e = entry.rsplit(' | ')
                self._diffstat[e[0].strip()] = e[1].strip()

        return self._diffstat

    def files(self, template='{files|json}'):
        return json.loads(execute(['hg', 'log', '-r', self.node(),
                                   '--template', template]))

    def file(self, filename):
        return execute(['hg', 'cat', '-r', self.node(), filename],
                       with_errors=False,
                       results_unicode=False)

    def merges(self):
        """Get all changeset of this merge change.

        If this is a merge changeset we can fetch
        all changesets that will be merged.
        """
        p = self.json['parents']
        if len(p) == 2 and self._merges is None:
            revset = 'ancestors({p2}) and ' \
                     '(children(ancestor(ancestor({p1}, {p2}),' \
                     '{node}))::' \
                     '{node})'.format(p1=p[0], p2=p[1], node=self.node())
            self._merges = MercurialRevision.fetch(revset)

        return self._merges


class GitRevision(BaseRevision):
    """Class to represent information of changeset."""
    @staticmethod
    def fetch(node, base):
        if base == '0000000000000000000000000000000000000000':
            rev = node
        else:
            rev = '%s..%s' % (base, node)
        changes = execute(['git', 'rev-list', rev]).splitlines()
        changes.reverse()

        result = []
        for entry in changes:
            known = execute(['git', 'branch', '--contains', entry])
            if len(known) > 0:
                continue
            result.append(GitRevision(entry))
        return result

    def __init__(self, hashnode):
        super(GitRevision, self).__init__()
        self._hash = hashnode
        self._merges = None
        self._diffstat = None

        pretty = '--pretty=format:%an <%ae>#%ai#%P#%B'
        data = execute(['git', 'log', '-1', self._hash, pretty])
        data = data.split('#', 4)
        self._user = data[0]
        self._date = data[1]
        self._parent = data[2]
        self._desc = data[3]

    def parent(self):
        return self._parent

    def node(self, short=True):
        return self._hash[:12] if short else self._hash

    def branch(self):
        return 'unknown'

    def author(self):
        return self._user

    def date(self):
        return self._date

    def desc(self):
        return self._desc

    def diffstat(self):
        return ''

    def files(self, template='{files|json}'):
        return []

    def file(self, filename):
        return ''

    def merges(self):
        """Get all changeset of this merge change.

        If this is a merge changeset we can fetch
        all changesets that will be merged.
        """
        return None


class BaseHook(object):
    """Class to represent a hook for Mercurial repositories."""

    def __init__(self, log, name, review_request_class, repo=None):
        self.log = log
        self.submitter = None
        self.repo_name = None
        self.repo_id = None
        self.root = None
        self.hgweb = None
        self.name = name
        self.review_request_class = review_request_class

        e = os.environ
        if 'KALLITHEA_EXTRAS' in e:
            kallithea = json.loads(e['KALLITHEA_EXTRAS'])
            self.repo_name = kallithea['repository']
            if 'default' in kallithea['username']:
                self.log('Anonymous access is not supported')
            else:
                self.submitter = kallithea['username']
        elif 'HEPTAPOD_USERINFO_USERNAME' in e and \
             'HEPTAPOD_PROJECT_PATH' in e and \
             'HEPTAPOD_PROJECT_NAMESPACE_FULL_PATH' in e:
            self.submitter = e['HEPTAPOD_USERINFO_USERNAME']
            self.repo_name = \
                e['HEPTAPOD_PROJECT_NAMESPACE_FULL_PATH'] + '/' + \
                e['HEPTAPOD_PROJECT_PATH']
        elif 'REPO_NAME' in e and 'REMOTE_USER' in e:
            self.submitter = e['REMOTE_USER']
            self.repo_name = e['REPO_NAME']
        else:
            self.submitter = getpass.getuser()
            if repo is not None:
                self.repo_name = repo

    def _set_repo_id(self):
        """Set ID of repository."""
        fields = 'path,mirror_path,id'

        repos = self.root.get_repositories(name=self.repo_name,
                                           tool=self.name,
                                           only_fields=fields,
                                           only_links='')

        if repos.num_items < 1:
            repos = self.root.get_repositories(path=self.repo_name,
                                               tool=self.name,
                                               only_fields=fields,
                                               only_links='')
            if repos.num_items < 1:
                raise HookError('Could not open Review Board repository:'
                                '\n%s\n'
                                'Repository is not registered or you do '
                                'not have permissions to access this '
                                'repository.' % self.repo_name)

        r = repos[0]
        self.repo_id = r.id
        for path in [r.path, r.mirror_path]:
            if path.startswith('http'):
                self.hgweb = path.rstrip('/')
                break

    def _set_root(self):
        """Set API root object."""
        cmd = MercurialGitHookCmd()
        try:
            server_url = cmd.get_server_url(None, None)
        except Exception as e:
            self.log('Trying .reviewboardrc (RBTOOLS_CONFIG_PATH) file "'
                     'in "%s" and "%s"',
                     os.environ.get('HOME'),
                     os.environ.get('RBTOOLS_CONFIG_PATH'))
            raise e

        self.log('Review Board: %s', server_url)
        api_client, self.root = cmd.get_api(server_url)
        session = get_authenticated_session(api_client, self.root,
                                            auth_required=True, num_retries=0)
        if session is None or not session.authenticated:
            raise HookError('Please add an USERNAME and a PASSWORD or '
                            'API_TOKEN to .reviewboardrc')

    def _check_duplicate(self, req, revreqs):
        """Check if a summary or commit_id is already used during this push.

        Args:
            req (rbtools.hooks.mercurial.MercurialReviewRequest):
                A review request object.

            revreqs (list of rbtools.hooks.mercurial.MercurialReviewRequest):
                All previous review requests.

        Returns:
            Boolean:
            True if summary or commit_id is duplicated, otherwise False.
        """
        return any(
            r.summary() == req.summary() or r.commit_id == req.commit_id
            for r in revreqs
        )

    def _handle_changeset_list(self, node, base=None):
        """Process all incoming changesets.

        Args:
            node (unicode):
                The hex of the first changeset.

        Returns:
            int:
            0 on success, otherwise non-zero.
        """
        changesets = self._list_of_incoming(node, base)
        revreqs = []
        self.log('Processing %d changeset(s)...', len(changesets))

        for changeset in changesets:
            request = self.review_request_class(self.root,
                                                self.repo_id,
                                                changeset,
                                                base,
                                                self.submitter)

            if self._check_duplicate(request, revreqs):
                self.log('Ignoring changeset (%s) as it has a '
                         'duplicated commit_id or summary: %s | %s',
                         request.node(),
                         request.commit_id,
                         request.summary())
                return 1

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
            self._log_push_info(revreqs[idx - 1].node())

        return 1

    def _log_push_info(self, node=None):
        self.log('If you want to push the already approved ')
        self.log('changes, you can (probably) execute this:')

    def _handle_review_request(self, request):
        """Handle given review request.

        Args:
            request (rbtools.hooks.mercurial.MercurialReviewRequest):
                A review request object.
        """
        if request.skippable():
            self.log('Skip changeset: %s | %s',
                     request.node(), request.failure)
            return

        if request.exists():
            if request.modified():
                request.sync()
                self.log('Updated review request (%d) for '
                         'changeset: %s', request.id(), request.node())
            else:
                if request.approved:
                    self.log('Found approved review request (%d) for '
                             'changeset: %s', request.id(),
                             request.node())
                else:
                    self.log('Found unchanged review request (%d) for '
                             'changeset: %s | %s', request.id(),
                             request.node(), request.failure)
        else:
            request.sync()
            self.log('Created review request (%d) for '
                     'changeset: %s', request.id(), request.node())

    def push_to_reviewboard(self, node, base=None):
        """Run the hook.

        Returns:
            int:
            Return code of execution. 0 on success, otherwise non-zero.
        """
        self.log('Push as user "%s" to "%s"...',
                 self.submitter, self.repo_name)

        if node is None or len(node) == 0:
            raise HookError('Initial changeset is undefined.')

        if self.submitter is None or self.repo_name is None:
            raise HookError('Cannot detect submitter or repository.')

        self._set_root()
        self._set_repo_id()
        return self._handle_changeset_list(node, base)


class MercurialHook(BaseHook):
    """Class to represent a hook for Mercurial repositories."""

    def __init__(self, log, repo=None):
        super(MercurialHook, self).__init__(log,
                                            'Mercurial',
                                            MercurialReviewRequest)

        if self.repo_name is None:
            self.repo_name = os.environ['HG_PENDING']

    def _list_of_incoming(self, node, base):
        """Return a list of all changesets after (and including) node.

        Assumes that all incoming changeset have subsequent revision numbers.

        Returns:
            list of object:
            The list of MercurialRevision.
        """
        return MercurialRevision.fetch(node + ':')

    def _log_push_info(self, node):
        super(MercurialHook, self)._log_push_info(node)
        self.log('hg push -r %s', node)


class GitHook(BaseHook):
    """Class to represent a hook for Git repositories."""

    def __init__(self, log, repo=None):
        super(GitHook, self).__init__(log, 'Git', GitReviewRequest)

        if self.repo_name is None:
            if os.environ.get('GIT_DIR') == '.':
                self.repo_name = os.getcwd()
                if self.repo_name.endswith('/.git'):
                    self.repo_name = self.repo_name[:-5]
            else:
                self.repo_name = os.environ.get('GIT_DIR')

    def _list_of_incoming(self, node, base):
        """Return a list of all changesets after (and including) node.

        Assumes that all incoming changeset have subsequent revision numbers.

        Returns:
            list of object:
            The list of GitRevision.
        """
        return GitRevision.fetch(node, base)

    def _log_push_info(self, node):
        super(GitHook, self)._log_push_info(node)
        self.log('git push origin %s:master', node)


def process_mercurial_hook(stdin, log):
    h = MercurialHook(log)
    node = os.environ.get('HG_NODE')
    base = MercurialRevision.normalize(node + '^1')
    sys.exit(h.push_to_reviewboard(node, base))


def process_git_hook(stdin, log):
    if stdin is None:
        lines = sys.stdin.readlines()
    elif isinstance(stdin, list):
        lines = stdin
    else:
        lines = stdin.splitlines()

    if len(lines) > 1:
        log('Push of multiple branches not supported')
        sys.exit(1)

    h = GitHook(log)
    (base, node, ref) = lines[0].split()
    sys.exit(h.push_to_reviewboard(node, base))


def main(stdin=None):
    import logging

    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=logging.INFO)
    logger = logging.getLogger('reviewboardhook')

    try:
        log = partial(logger.info)
        if 'HG_NODE' in os.environ:
            logger.debug('Mercurial detected...')
            process_mercurial_hook(stdin, log)
        else:
            logger.debug('Git detected...')
            process_git_hook(stdin, log)

    except Exception as e:
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.exception('Backtrace of error: %s' % e)
        else:
            for line in six.text_type(e).split('\n'):
                logger.error(line)

    sys.exit(-1)


if __name__ == '__main__':
    main()
