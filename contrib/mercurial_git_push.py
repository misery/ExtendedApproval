#!/usr/bin/env python
"""A Mercurial/git hook to post to Review Board on push to a central server.

The hook was designed to make posting to Review Board easy.
It allows user to post to Review Board by using the
ordinary 'hg push' or 'git push', without any need to learn or
install RBTools locally.

The hook with Review Board tries to act like gerrit for git.
Every changeset is a review request that will be amended until it is
marked as "Ship It!".

Look also to reviewboard extension "Extended Approval"
to have better control over the "approved" flag.

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





###### SetUp

The hook submits review requests using the username of the current user.
You need to configure a "hook" user in Review Board with the following rights:
 Section: reviews | review request
  - 'Can edit review request'
  - 'Can submit as another user'
  - 'Can change status'
Instead of the rights above you could set the "hook" user as an administrator.


Those credentials can be configured through a global .reviewboardrc
file on server. This file needs to be in the HOME directory of the
server user or you need to define RBTOOLS_CONFIG_PATH.

See reviewboardrc config file.
REVIEWBOARD_URL: The URL of the Review Board server
USERNAME: The username to use for logging into the server
PASSWORD: The password to use for logging into the server
API_TOKEN: An API token to use for logging into the server. This is
           recommended and replaces the use of PASSWORD.


Also you need to install rbtools as the hook uses this.
It is recommended to use current version from pypi: pip install -U rbtools

Also it is recommended to use a virtualenv for this to have a clean
environment: https://docs.python.org/3/tutorial/venv.html





### Mercurial
You need to add the hook to your .hg/hgrc file of your repository or use
a global/system-wide .hgrc file to define the hook for all repositories once.

Hint:
  Use "/etc/gitlab/heptapod.hgrc" as the system-wide config for Heptapod.


If you use a virtualenv or want some special changes for the hook you
can use the provided reviewboard.sh as a wrapper to the hook.

[hooks]
pretxnchangegroup.rb = /path/to/hook/mercurial_git_push.py
#pretxnchangegroup.rb = /path/to/hook/reviewboard.sh

This hook was tested with "hg serve", Heptapod, Kallithea and SCM-Manager
as a remote hosting platform and a local repository.



### Git
You need to add this hook as a pre-receive script to .git/hooks or use
$GIT_DIR and the core.hooksPath configuration.

See: https://git-scm.com/docs/githooks

$ ln -s /to/hook/mercurial_git_push.py /to/repo/.git/hooks/pre-receive
or
$ ln -s /to/hook/reviewboard.sh /to/repo/.git/hooks/pre-receive
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
from functools import partial

from rbtools import __version__ as rbversion
from rbtools.clients.git import GitClient
from rbtools.clients.mercurial import MercurialClient
from rbtools.commands import Command
from rbtools.hooks.common import HookError
from rbtools.utils.filesystem import is_exe_in_path
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

HG = 'hg'


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

            if self._is_diff_empty(parent_diff):
                self._parent_diff = None
            else:
                self._parent_diff = parent_diff

        def _is_diff_empty(self, diff):
            return diff is None or len(diff) == 0

        def getDiff(self):
            return self._diff

        def setDiff(self, diff):
            self._hashes = {}
            self._parent_diff = None
            if self._is_diff_empty(diff):
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

    def __init__(self, tool, request_id):
        """Initialize object with the given API root."""
        self.tool = tool
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
        if rbversion >= '1.0.4':
            tool = MercurialClient(HG)
        else:
            tool = MercurialClient()
        cmd = Command()
        tool.capabilities = cmd.get_capabilities(api_root=root)

        super(MercurialDiffer, self).__init__(tool, request_id)


class GitDiffer(BaseDiffer):
    def __init__(self, root, request_id):
        tool = GitClient()
        tool.get_repository_info()
        super(GitDiffer, self).__init__(tool, request_id)


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

    def graft(self, short=True):
        """Return changeset as hex node."""
        return self._changeset.graft(short)

    def parent(self):
        """Return changeset as hex node."""
        return self._changeset.parent()

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

    def close(self, web=None):
        """Close the given review request with a message."""
        rev = self.node()
        text_type = 'plain'
        if web is not None:
            text_type = 'markdown'
            web = web.format(rev)
            rev = '[{0}]({1})'.format(rev, web)

        msg = 'Automatically closed by a push (hook): %s' % rev
        self.request.update(status='submitted',
                            close_description=msg,
                            close_description_text_type=text_type)

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
        return None

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
                 r'\[[0-9|a-z|/]+\]')
        regex = re.compile(regex)

        old = self.request.description
        new = self._info()
        return regex.sub('', old, 1) != regex.sub('', new, 1)

    def _commit_id_data(self):
        content = []

        content.append(self._changeset.author().encode('utf-8'))
        content.append(self._changeset.date().encode('utf-8'))
        content.append(six.text_type(self.repo).encode('utf-8'))

        s = self.summary()
        if (s.startswith('[maven-release-plugin]') or
                s.startswith('Added tag ') or
                s.startswith('Moved tag ') or
                s.startswith('Removed tag ')):
            content.append(s)

        return content

    def _generate_commit_id(self):
        """Return a commit id of the changeset.

        Returns:
            unicode:
            A generated commit id of changeset.
        """
        hasher = hashlib.md5()

        for line in self._commit_id_data():
            hasher.update(line)

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

    def _commit_id_data(self):
        content = super(MercurialReviewRequest, self)._commit_id_data()

        graft = self.graft(False)
        if graft:
            content.append(graft)

        return content

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

    def _generate_diff_info(self):
        """Generate the diff if it has been changed.

        Fake a diff if the diff cannot be created!
        This will happend for the following commands:
        - A commit for new branch: "hg branch" and "hg push --new-branch"
        - A commit to close a branch: "hg commit --close-branch"
        """
        differ = MercurialDiffer(self.root, self.request.id)
        self.diff_info = differ.diff(self.parent(),
                                     self.node(False),
                                     self.base)

        if self.diff_info.getDiff() is None:
            content = []
            for data in self._changeset.raw_data():
                content.append(b'+%s' % data)

            fake_diff = FAKE_DIFF_TEMPL % (len(content) + 5,
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
                                     self.node(False),
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
            template = ('{author} ({date}) [{node}] '
                        '[{branch}] [graft: {graft}]:\n{desc}')

            self._info = template.format(author=self.author(),
                                         date=self.date(),
                                         node=self.node(),
                                         branch=self.branch(),
                                         graft=self.graft(),
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
        changes = execute([HG, 'log', '--debug',
                           '--config', 'ui.message-output=stderr',
                           '-r', revset, '--template', 'json'],
                          with_errors=False,
                          return_errors=False)

        result = []
        for entry in json.loads(changes):
            result.append(MercurialRevision(entry))
        return result

    def __init__(self, json):
        super(MercurialRevision, self).__init__()
        self.json = json
        self._date = None
        self._merges = None
        self._diffstat = None
        self._graft_source = None
        self._raw_data = None

    def graft(self, short=True):
        if self._graft_source is None:
            self._graft_source = ''

            if 'extra' in self.json:
                if 'source' in self.json['extra']:
                    self._graft_source = self.json['extra']['source']

        if len(self._graft_source) > 0:
            return self._graft_source[:12] if short else self._graft_source

        return None

    def parent(self, short=False):
        p = self.json['parents'][0]
        return p[:12] if short else p

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
            o = execute([HG, 'diff', '-g',
                         '--stat', '-c', self.node()]).splitlines()
            del o[-1]  # useless summary line
            for entry in o:
                e = entry.rsplit(' | ')
                self._diffstat[e[0].strip()] = e[1].strip()

        return self._diffstat

    def files(self, template='{files|json}'):
        return json.loads(execute([HG, 'log', '-r', self.node(),
                                   '--template', template]))

    def file(self, filename):
        return execute([HG, 'cat', '-r', self.node(), filename],
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

    def raw_data(self):
        if self._raw_data is None:
            detail = 'changeset: {node}\n' \
                     'branch:    {branch}\n' \
                     'parent:    {p1node}\n' \
                     'parent:    {p2node}\n' \
                     'user:      {author}\n' \
                     'date:      {localdate(date, "UTC")|date}\n' \
                     'extra:     {join(extras, "\nextra:     ")}\n'
            cmd = [HG, 'log', '-T', detail, '-r', self.node()]
            content = execute(cmd, results_unicode=False)
            self._raw_data = content.strip().splitlines()

        return self._raw_data


class GitRevision(BaseRevision):
    """Class to represent information of changeset."""
    @staticmethod
    def fetch(node, base, refs=None, skipKnown=True):
        if base == '0000000000000000000000000000000000000000':
            rev = node
        else:
            rev = '%s..%s' % (base, node)
        changes = execute(['git', 'rev-list', rev]).splitlines()
        changes.reverse()

        result = []
        for entry in changes:
            if skipKnown:
                known = execute(['git', 'branch', '--contains', entry])
                if len(known) > 0:
                    continue
            result.append(GitRevision(entry, refs))
        return result

    def __init__(self, hashnode, refs):
        super(GitRevision, self).__init__()
        self._hash = hashnode
        self._refs = refs.replace('refs/heads/', '') if refs else None
        self._merges = None

        pretty = '--pretty=format:%an <%ae>#%ai#%P#%B'
        data = execute(['git', 'log', '-1', self._hash, pretty])
        data = data.split('#', 4)
        self._user = data[0]
        self._date = data[1]
        self._parent = data[2].split()
        self._desc = data[3]

    def graft(self):
        return None

    def parent(self):
        return self._parent

    def node(self, short=True):
        return self._hash[:12] if short else self._hash

    def branch(self):
        return self._refs

    def author(self):
        return self._user

    def date(self):
        return self._date

    def desc(self):
        return self._desc

    def diffstat(self):
        return ''

    def files(self):
        return []

    def file(self, filename):
        entry = '%s:%s' % (self.node(False), filename)
        return execute(['git', 'show', entry])

    def merges(self):
        """Get all changeset of this merge change.

        If this is a merge changeset we can fetch
        all changesets that will be merged.
        """
        if self._merges is None and len(self._parent) > 1:
            self._merges = GitRevision.fetch(self._hash,
                                             self._parent[0],
                                             skipKnown=False)
            self._merges.pop()  # remove merge commit itself
            self._merges.reverse()  # use correct order

        return self._merges


class BaseHook(object):
    """Class to represent a hook for Mercurial repositories."""

    def __init__(self, log, name, review_request_class, repo=None):
        self.log = log
        self.submitter = None
        self.repo_name = None
        self.repo_id = None
        self.root = None
        self.web = None
        self.base = None
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
        elif 'GL_USERNAME' in e and 'GL_PROJECT_PATH' in e:
            self.submitter = e['GL_USERNAME']
            self.repo_name = e['GL_PROJECT_PATH']
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
        return r

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

        try:
            api_client, self.root = cmd.get_api(server_url)
        except Exception as e:
            self.log('Cannot fetch data from RB. Is ALLOWED_HOST correct?')
            raise e

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
        self.log('Processing %d changeset(s)...', len(changesets))

        if self.base is None and len(changesets) > 0:
            self.base = changesets[0].parent()
            if isinstance(self.base, list):
                self.base = self.base[0]

        return self._handle_changeset_list_process(node, changesets)

    def _handle_changeset_list_process(self, node, changesets):
        revreqs = []
        for changeset in changesets:
            request = self.review_request_class(self.root,
                                                self.repo_id,
                                                changeset,
                                                self.base,
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
                r.close(self.web)
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

    def push_to_reviewboard(self, node):
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
        return self._handle_changeset_list(node)


class MercurialHook(BaseHook):
    """Class to represent a hook for Mercurial repositories."""

    def __init__(self, log, repo=None):
        super(MercurialHook, self).__init__(log,
                                            'Mercurial',
                                            MercurialReviewRequest)

        if self.repo_name is None:
            self.repo_name = os.environ['HG_PENDING']

    def _list_of_incoming(self, node):
        """Return a list of all changesets after (and including) node.

        Assumes that all incoming changeset have subsequent revision numbers.

        Returns:
            list of object:
            The list of MercurialRevision.
        """
        return MercurialRevision.fetch(node + ':')

    def _set_repo_id(self):
        r = super(MercurialHook, self)._set_repo_id()
        for path in [r.path, r.mirror_path]:
            if path.startswith('http'):
                self.web = path.rstrip('/') + '/rev/{0}'
                break

    def _log_push_info(self, node):
        super(MercurialHook, self)._log_push_info(node)
        self.log('hg push -r %s', node)


class GitHook(BaseHook):
    """Class to represent a hook for Git repositories."""

    def __init__(self, log, base, refs, repo=None):
        super(GitHook, self).__init__(log, 'Git', GitReviewRequest)
        self.refs = refs
        self.base = base

        if self.repo_name is None:
            if os.environ.get('GIT_DIR') == '.':
                self.repo_name = os.getcwd()
                if self.repo_name.endswith('/.git'):
                    self.repo_name = self.repo_name[:-5]
            else:
                self.repo_name = os.environ.get('GIT_DIR')

    def _handle_changeset_list_process(self, node, changesets):
        if len(changesets) > 1:
            for rev in changesets:
                if len(rev.parent()) > 1:
                    self.log('Merge cannot be pushed with other commits: %s',
                             rev.node())
                    return 1

        return super(GitHook, self)._handle_changeset_list_process(node,
                                                                   changesets)

    def _list_of_incoming(self, node):
        """Return a list of all changesets after (and including) node.

        Assumes that all incoming changeset have subsequent revision numbers.

        Returns:
            list of object:
            The list of GitRevision.
        """
        return GitRevision.fetch(node, self.base, self.refs)

    def _log_push_info(self, node):
        super(GitHook, self)._log_push_info(node)
        self.log('git push origin %s:master', node)


def process_mercurial_hook(stdin, log):
    CHG = 'chg'
    if is_exe_in_path(CHG):
        global HG
        os.environ['CHGHG'] = HG
        HG = CHG

    h = MercurialHook(log)
    node = os.environ.get('HG_NODE')
    return h.push_to_reviewboard(node)


def process_git_hook(stdin, log):
    if stdin is None:
        lines = sys.stdin.readlines()
    elif isinstance(stdin, list):
        lines = stdin
    else:
        lines = stdin.splitlines()

    if len(lines) > 1:
        log('Push of multiple branches not supported')
        return 1

    (base, node, ref) = lines[0].split()
    h = GitHook(log, base, ref)
    return h.push_to_reviewboard(node)


def get_logging_level(logging):
    DEBUG = 'HG_USERVAR_DEBUG'
    if DEBUG in os.environ and os.environ[DEBUG].lower() in ('true', 'on'):
        return logging.DEBUG

    return logging.INFO


def hook(stdin=None):
    import logging

    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=get_logging_level(logging))
    logger = logging.getLogger('reviewboardhook')

    try:
        log = partial(logger.info)
        if 'HG_NODE' in os.environ:
            logger.debug('Mercurial detected...')
            return process_mercurial_hook(stdin, log)
        else:
            logger.debug('Git detected...')
            return process_git_hook(stdin, log)

    except Exception as e:
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.exception('Backtrace of error: %s' % e)
        else:
            for line in six.text_type(e).split('\n'):
                logger.error(line)

    return -1


if __name__ == '__main__':
    import sys
    sys.exit(hook())
