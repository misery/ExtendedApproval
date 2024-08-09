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


This hook was tested with "hg serve", hgkeeper, Heptapod, Kallithea,
SCM-Manager, Gitea and Gogs as a remote hosting platform
and a local repository.



### Mercurial
You need to add the hook to your .hg/hgrc file of your repository or use
a global/system-wide .hgrc file to define the hook for all repositories once.

Hint:
  Use "/etc/gitlab/heptapod.hgrc" as the system-wide config for Heptapod.


If you use a virtualenv or want some special changes for the hook you
can use the provided reviewboard.sh as a wrapper to the hook.

[hooks]
pretxnclose.rb = /path/to/hook/mercurial_git_push.py
#pretxnclose.rb = /path/to/hook/reviewboard.sh



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
import logging
import os
import re
import six

from rbtools import __version__ as rbversion
from rbtools.api.resource import FileDiffResource
from rbtools.clients.git import GitClient
from rbtools.clients.mercurial import MercurialClient
from rbtools.hooks.common import HookError
from rbtools.utils.filesystem import is_exe_in_path
from rbtools.utils.process import execute
from rbtools.utils.users import get_authenticated_session

try:
    from rbtools.commands.base import BaseCommand
except ImportError:
    from rbtools.commands import Command as BaseCommand

if rbversion >= '5':
    from rbtools.utils.mimetypes import (guess_mimetype,
                                         match_mimetype,
                                         parse_mimetype)

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

log = logging.getLogger('reviewboardhook')
HG = 'hg'
OPTIONS = None
SERVER = None
KEY = None
KEY_ENV = 'HOOK_HMAC_KEY'


def getHMac():
    global KEY

    if KEY is None:
        KEY = os.environ.get(KEY_ENV)
        if KEY is None:
            try:
                with open('/etc/machine-id', 'r') as content_file:
                    KEY = content_file.read().strip()
            except Exception:
                raise HookError('You need to define %s' % KEY_ENV)

        if not six.PY2:
            KEY = bytes(KEY, 'utf-8')

    return hmac.new(KEY, digestmod=hashlib.sha256)


def hasCapability(*capability):
    if SERVER is None:
        return False
    return SERVER.has_capability(*capability)


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

            hasher = getHMac()
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

            prefixes = (b'diff', b'@@', b'#', b'index')

            for line in self._diff.splitlines():
                if len(line) > 0 and not line.startswith(prefixes):
                    hasher.update(line)

            h = hasher.hexdigest()
            self._hashes[diffset_id] = h
            return h

    def __init__(self, tool):
        self.tool = tool

    def diff(self, rev1, rev2, base, request_id):
        """Return a diff and parent diff of given changeset.

        Args:
            rev1 (unicode):
                Last public revision.

            rev2 (unicode):
                Revision of current changeset.

            base (unicode):
                Base revision of current changeset.

            request_id (unicode):
                ID of current review request.

        Returns:
            map:
            The diff information of the changeset.
        """
        revisions = {'base': rev1, 'tip': rev2}

        # Avoid generating of empty parent diff
        # If 'base' and 'parent_base' is the same this is the
        # first new changeset. So there is no parent diff!
        if revisions['base'] != base and base is not None:
            revisions['parent_base'] = base

        info = self.tool.diff(revisions=revisions, binaries=True)
        return BaseDiffer.DiffContent(request_id,
                                      info['diff'],
                                      info['base_commit_id'],
                                      info['parent_diff'])


class MercurialDiffer(BaseDiffer):
    def __init__(self, root, cmd):
        if rbversion >= '1.0.4':
            tool = MercurialClient(executable=HG)
        else:
            tool = MercurialClient()

        if rbversion >= '3':
            tool.capabilities = cmd.capabilities
        else:
            tool.capabilities = cmd.get_capabilities(api_root=root)

        super(MercurialDiffer, self).__init__(tool)


class GitDiffer(BaseDiffer):
    def __init__(self, root, cmd):
        tool = GitClient()
        tool.get_repository_info()
        super(GitDiffer, self).__init__(tool)


class BaseReviewRequest(object):
    """A class to represent a review request from a Mercurial hook."""

    def __init__(self, root, repo, changesets,
                 submitter, differ, web, topic):
        """Initialize object with the given information.

        Args:
            root (complex):
                The API root resource.

            repo (int):
                An ID of repository.

            changesets (list of MercurialRevisions):
                A list of MercurialRevision objects.

            submitter (unicode):
                The username of current submitter.

            differ (BaseDiffer):
                An object to generate diffs.

            web (unicode, optional):
                URL to web repository.

            topic (unicode, optional):
                The name of the topic.
        """
        self.root = root
        self.repo = repo
        self.submitter = submitter
        self._topic_prefix = 'Topic: '
        self._topic = topic
        self._changesets = changesets
        self._check_changesets()
        self.commit_id = self._generate_commit_id()
        self.diff_info = None
        self.diff_info_commits = None
        self._depends_on = None
        self._depends_on_updated = None
        self._skippable = None
        self._differ = differ
        self._web = web
        self._web_node_regex = re.compile(r'\b([0-9|a-f]{40}|[0-9|a-f]{12})\b')
        self._web_backref = (
            r'[\g<0>]({0}\g<0>)'.format(web.format('')) if web else None
        )
        self._info = None

        regex = os.environ.get('HOOK_FILE_UPLOAD_REGEX')
        if not regex:
            regex = r'.*\.(png|jpg|jpeg|gif|svg|webp|ico|bmp)$'
        self.regexUpload = re.compile(regex)

        r = self._get_request()
        self.request = r
        self._existing = False if r is None else True
        self._failure = None if r is None else r.approval_failure
        self._approved = False if r is None or self.skippable() else r.approved

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

    def approved(self):
        return self._approved

    def failure(self):
        return self._failure

    def changesets(self):
        return self._changesets

    def nodes(self, short=True):
        """Return changeset(s) as hex node."""
        nodes = []
        for changeset in self._changesets:
            nodes.append(changeset.node(short))
        return ','.join(nodes)

    def branch(self):
        """Return branch of changeset(s)."""
        return self._changesets[0].branch()

    def summary(self):
        if self._topic:
            return self._topic_prefix + self._topic
        else:
            return self._changesets[0].summary()

    def _should_skip(self, rev):
        return None

    def skippable(self):
        if self._skippable is None:
            self._skippable = False
            regex = r'Reviewed at https://'

            for changeset in self._changesets:
                if changeset.summary().startswith('SKIP'):
                    self._skippable = True
                    self._failure = 'Starts with SKIP'
                    break
                elif re.search(regex, changeset.desc()):
                    self._skippable = True
                    self._failure = 'Description contains: "%s"' % regex
                    break

                skip = self._should_skip(changeset)
                if skip is not None:
                    self._skippable = True
                    self._failure = skip
                    break

        return self._skippable

    def _replace_hashes(self, content):
        if self._web_backref is not None:
            content = self._web_node_regex.sub(self._web_backref, content)
        return content

    def _markdown_rev(self, rev):
        text_type = 'plain'

        if self._web is not None:
            text_type = 'markdown'
            splitChar = ','
            revs = []
            for node in rev.split(splitChar):
                web = self._web.format(node)
                revs.append('[{0}]({1})'.format(node, web))
            rev = splitChar.join(revs)

        return (rev, text_type)

    def _info_template(self):
        if self.request.created_with_history:
            return ('```{author} '
                    '[{branch}] [graft: {graft}] '
                    '```\n\n{desc}')
        else:
            return ('```{author} ({date}) [{node}] '
                    '[{branch}] [graft: {graft}] '
                    '[topic: {topic}]'
                    '```\n\n{desc}')

    def info(self):
        if self._info is None:
            template = self._info_template()
            self._info = []
            for changeset in self._changesets:
                desc = self._replace_hashes(changeset.desc())
                info = template.format(author=changeset.author(),
                                       date=changeset.date(),
                                       node=changeset.node(True),
                                       branch=changeset.branch(),
                                       graft=changeset.graft(),
                                       topic=changeset.topic(),
                                       desc=desc)

                merges = changeset.merges()
                if merges:
                    info += '\n\n\n'

                    files = changeset.files()
                    info += '# Touched %d file(s) by this merge ' \
                            'changeset\n' % len(files)
                    for entry in files:
                        info += '+ ' + entry + '\n'

                    info += '# Merges %d changeset(s)\n' % len(merges)

                    def add(changes):
                        i = ''
                        t = '+ [{node}] {summary}\n'
                        for rev in changes:
                            node, _ = self._markdown_rev(rev.node(True))
                            summary = self._replace_hashes(rev.summary())
                            i += t.format(node=node, summary=summary)
                        return i

                    if len(merges) > MAX_MERGE_ENTRIES + 1:
                        info += add(merges[0:MAX_MERGE_ENTRIES])
                        info += '+ ...\n'
                        info += add([merges[-1]])
                    else:
                        info += add(merges)

                self._info.append(info.strip())

            self._info = '\n\n---\n'.join(self._info)

        return self._info

    def exists(self):
        """Return existence of review request.

        Returns:
            Boolean:
            True if review request exists, otherwise False.
        """
        return self._existing

    def modified(self):
        """Return modified state of review request.

        Returns:
            Boolean:
            True if review request is modified, otherwise False.
        """
        return (self.request.branch != self.branch() or
                self.request.summary != self.summary() or
                self._get_depends_on() != self._get_depends_on_updated() or
                self._modified_description() or not
                self._diff_up_to_date())

    def close(self):
        """Close the given review request with a message."""
        rev, text_type = self._markdown_rev(self.nodes())
        msg = 'Automatically closed by a push (hook): %s' % rev
        self.request.update(status='submitted',
                            close_description=msg,
                            close_description_text_type=text_type)

    def sync(self):
        """Synchronize review request on review board."""
        if 'NOSYNC' in OPTIONS:
            return False

        if self.request is None:
            self.request = self._create()

        if self.diff_info is None:
            self._generate_diff_info()

        self._update()
        return True

    def _check_changesets(self):
        if len(self._changesets) == 1:
            return

        if self._topic is None:
            raise HookError('Topic is required for multiple commits')

        branch = None
        prevNode = None
        for changeset in self._changesets:
            if prevNode is not None and changeset.parent() != prevNode:
                raise HookError('Topic may only be linear: %s' % self._topic)
            prevNode = changeset.node()

            if changeset.isMerge():
                raise HookError('Topic changeset is a merge: '
                                '%s' % changeset.node())

            if branch is None:
                branch = changeset.branch()
            elif changeset.branch() != branch:
                raise HookError('Topic changesets uses multiple branches: '
                                '%s / %s' % (branch, changeset.branch()))

    def _get_hash(self, diffset_id):
        if self.request.created_with_history:
            hasher = getHMac()
            for info in six.itervalues(self.diff_info_commits):
                hasher.update(info.getHash(diffset_id).encode('utf-8'))
            hasher.update(self.info().encode('utf-8'))
            if self._topic:
                hasher.update(self._topic.encode('utf-8'))
            return hasher.hexdigest()

        return self.diff_info.getHash(diffset_id)

    def _diff_up_to_date(self):
        """Return modified state of diff.

        Returns:
            Boolean:
            True if diff is up to date, otherwise False.
        """
        if self.diff_info is None:
            self._generate_diff_info()

        if (
            not self.exists()
            or self.diffset_id is None
            or 'UPDATE' in OPTIONS
        ):
            return False

        e = self.request.extra_data
        return ('diff_hash' in e and
                self._get_hash(self.diffset_id) == e['diff_hash'])

    def _update_attachments(self, uploaded):
        return None

    def _upload_diff_attachments(self, files):
        if len(files) < 1:
            return

        fields = 'repository_file_path,repository_revision'
        api = self.root.get_diff_file_attachments(repository_id=self.repo,
                                                  only_fields=fields,
                                                  only_links='create,self')
        maxSize = SERVER.get_capability('diffs', 'max_binary_size')

        supportedMimetypes = [
            parse_mimetype(mimetype) for mimetype in
            SERVER.get_capability('review_uis', 'supported_mimetypes')
        ]

        def isKnown(filename, rev):
            for a in api.all_items:
                if (
                    a.repository_file_path == filename and
                    a.repository_revision == rev
                ):
                    return True
            return False

        def upload(id, filename, revision, source_file=False):
            valid_mimetypes = []
            invalid_mimetypes = []

            def supported(content):
                mime = guess_mimetype(content)
                if not mime or mime in invalid_mimetypes:
                    return False

                if mime in valid_mimetypes:
                    return True

                valid = any(match_mimetype(pattern, parse_mimetype(mime))
                            for pattern in supportedMimetypes)
                if valid:
                    valid_mimetypes.append(mime)
                else:
                    invalid_mimetypes.append(mime)

                return valid

            size = self._differ.tool.get_file_size(filename=filename,
                                                   revision=revision)

            if size > maxSize:
                log.info('File too large to upload: %s (%s)',
                         filename, revision)
                return

            content = self._differ.tool.get_file_content(filename=filename,
                                                         revision=revision)

            if supported(content):
                log.info('Upload binary "%s" in revision %s',
                         filename, revision)
                api.upload_attachment(
                    filename=os.path.basename(filename),
                    content=content,
                    filediff_id=id,
                    source_file=source_file)

        for f in files:
            if f.status == 'deleted':
                continue

            upload(f.id, f.dest_file, f.dest_detail)

            if (
                'parent_source_revision' in f.extra_data and
                f.source_revision != 'PRE-CREATION' and
                not isKnown(f.source_file, f.source_revision)
            ):
                upload(f.id, f.source_file, f.source_revision, True)

    def _update_with_history(self, diffs):
        d = self.diff_info
        v = None
        validator = self.root.get_commit_validation()

        for changeset in self._changesets:
            change_d = self.diff_info_commits[changeset.node()]
            v = validator.validate_commit(repository=self.repo,
                                          diff=change_d.getDiff(),
                                          commit_id=changeset.node(),
                                          parent_id=changeset.parent(),
                                          parent_diff=d.getParentDiff(),
                                          base_commit_id=d.getBaseCommitId(),
                                          validation_info=v
                                          ).validation_info

        diff = diffs.create_empty(base_commit_id=d.getBaseCommitId(),
                                  only_fields='',
                                  only_links='self,draft_commits')
        c = diff.get_draft_commits()
        binaries: list[FileDiffResource] = []
        for changeset in self._changesets:
            change_d = self.diff_info_commits[changeset.node()]
            upload = c.upload_commit(validation_info=v,
                                     commit_id=changeset.node(),
                                     commit_message=changeset.desc(),
                                     parent_id=changeset.parent(),
                                     parent_diff=d.getParentDiff(),
                                     diff=change_d.getDiff(),
                                     author_name=changeset.authorName(),
                                     author_email=changeset.mail(),
                                     author_date=changeset.date(),
                                     committer_name=changeset.authorName(),
                                     committer_email=changeset.mail(),
                                     committer_date=changeset.date()
                                     )
            binaries += upload.get_draft_files(binary=True).all_items

        diff.finalize_commit_series(cumulative_diff=d.getDiff(),
                                    validation_info=v,
                                    parent_diff=d.getParentDiff()
                                    )
        return binaries

    def _update(self):
        """Update review request draft based on changeset."""
        self._approved = False
        extra_data = None
        draft = self.request.get_or_create_draft(only_fields='',
                                                 only_links='update,'
                                                            'draft_diffs')
        binaries = []
        if not self._diff_up_to_date():
            diffs = draft.get_draft_diffs(only_links='upload_diff,'
                                                     'draft_files',
                                          only_fields='')

            if self.request.created_with_history:
                binaries = self._update_with_history(diffs)
            else:
                if len(self._changesets) > 1:
                    raise HookError('Cannot use ReviewRequest '
                                    'with multiple changesets: %d'
                                    % self.request.id)

                d = self.diff_info
                upload = diffs.upload_diff(diff=d.getDiff(),
                                           parent_diff=d.getParentDiff(),
                                           base_commit_id=d.getBaseCommitId())
                if rbversion >= '1.0.2':
                    binaries = list(upload.get_draft_files(binary=True)
                                    .all_items)

            # re-fetch diffset to get id
            diffs = draft.get_draft_diffs(only_links='draft_commits',
                                          only_fields='id')
            extra_data = {'extra_data.diff_hash': self._get_hash(diffs[0].id)}

            binarySupportRB7 = (rbversion >= '5' and
                                hasCapability('diffs', 'file_attachments'))
            if binarySupportRB7:
                self._upload_diff_attachments(binaries)
            if (
                  rbversion >= '1.0.3' and
                  not self.request.created_with_history
            ):
                uploaded = binaries if binarySupportRB7 else []
                h = self._update_attachments(uploaded)
                extra_data['extra_data.file_hashes'] = h

        refs = []
        for changeset in self._changesets:
            refs.extend([six.text_type(x)
                        for x in get_ticket_refs(changeset.desc())])
        refs = list(set(refs))
        refs.sort()
        bugs = ','.join(refs)
        depends_on = self._get_depends_on_updated()

        draft.update(summary=self.summary(),
                     depends_on=','.join(depends_on),
                     bugs_closed=bugs,
                     description=self.info(),
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
                        create_with_history=self._topic is not None,
                        submit_as=self.submitter)

    def _get_depends_on(self):
        if self._depends_on is None:
            self._depends_on = []
            for request in self.request.depends_on:
                ID = re.search(r'\/([0-9]+)\/*$', request['href'])
                if ID and ID.group(1):
                    self._depends_on.append(ID.group(1))
                else:
                    self._depends_on.append(str(request.get().id))

        return self._depends_on

    def _get_depends_on_updated(self):
        if self._depends_on_updated is None:
            self._depends_on_updated = list(self._get_depends_on())

            changesetTopic = self._changesets[0].topic()
            if self._topic is None and changesetTopic is not None:
                fields = ('summary,id')
                links = ('diff_context')
                summary = self._topic_prefix + changesetTopic
                requests = self._get_requests_from_summary(fields,
                                                           links,
                                                           summary)
                summary = self._changesets[0].summary()
                for r in requests:
                    ctx = r.get_diff_context()
                    if ctx.commits is None:
                        continue
                    for commit in ctx.commits:
                        if commit.commit_message.splitlines()[0] == summary:
                            ID = str(r.id)
                            if ID not in self._depends_on_updated:
                                self._depends_on_updated.append(ID)

        return self._depends_on_updated

    def _modified_description(self):
        """Filter changeset information and check if the
           description got changed.
        """
        if self.request.created_with_history:
            return False

        regex = (r'\([0-9]{4}-[0-9]{2}-[0-9]{2} '
                 r'[0-9]{2}:[0-9]{2}:[0-9]{2}'
                 r'[\s]{0,1}[+-][0-9]{2}[:]{0,1}[0-9]{2}\) '
                 r'\[[0-9|a-z]*\]')
        regex = re.compile(regex)

        old = self.request.description
        new = self.info()
        return regex.sub('', old, 1) != regex.sub('', new, 1)

    def _commit_id_data(self):
        content = []

        if self._topic:
            content.append(self._topic.encode('utf-8'))

        content.append(self._changesets[0].author().encode('utf-8'))
        content.append(self._changesets[0].date().encode('utf-8'))
        content.append(six.text_type(self.repo).encode('utf-8'))

        if self._topic is None:
            s = self.summary()
            if (s.startswith('[maven-release-plugin]') or
                    s.startswith('Added tag ') or
                    s.startswith('Moved tag ') or
                    s.startswith('Removed tag ')):
                content.append(s.encode('utf-8'))

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
        fields = ('summary,approved,approval_failure,id,commit_id,depends_on,'
                  'branch,description,extra_data,created_with_history')
        links = 'submitter,update,latest_diff,draft,file_attachments'

        reqs = self.root.get_review_requests(repository=self.repo,
                                             status='pending',
                                             show_all_unpublished=True,
                                             only_fields=fields,
                                             only_links=links,
                                             commit_id=self.commit_id)

        count = len(reqs)
        if count == 0:
            reqs = self._get_requests_from_summary(fields,
                                                   links,
                                                   self.summary())
            if len(reqs) == 1:
                return reqs[0]
            elif len(reqs) > 1:
                IDs = []
                [IDs.append(str(r.id)) for r in reqs]
                raise HookError('Found multiple review requests for summary '
                                '"%s": %s'
                                % (self.summary(), ','.join(IDs)))

        elif count == 1:
            r = reqs[0]
            if r.links.submitter.title.lower() != self.submitter.lower():
                raise HookError('Owner of review request (%d): %s'
                                % (r.id, r.links.submitter.title))
            return r

        return None

    def _get_requests_from_summary(self, fields, links, summary):
        reqs = self.root.get_review_requests(repository=self.repo,
                                             status='pending',
                                             show_all_unpublished=True,
                                             only_fields=fields,
                                             only_links=links,
                                             from_user=self.submitter)
        found = []
        for r in reqs.all_items:
            if r.summary == summary:
                found.append(r)

        return found

    def _check_and_set_fake_diff(self, diff_info, changesets):
        pass

    def _generate_diff(self, parent, node, base):
        return self._differ.diff(parent, node, base, self.request.id)

    def _generate_diff_info(self):
        self.diff_info = self._generate_diff(self._changesets[0].parent(),
                                             self._changesets[-1].node(),
                                             self._changesets[0].base())
        self._check_and_set_fake_diff(self.diff_info, self._changesets)

        self.diff_info_commits = {}
        if self.request.created_with_history:
            if len(self._changesets) == 1:
                node = self._changesets[0].node()
                self.diff_info_commits[node] = self.diff_info
            else:
                for changeset in self._changesets:
                    info = self._generate_diff(changeset.parent(),
                                               changeset.node(),
                                               None)
                    self._check_and_set_fake_diff(info, [changeset])
                    self.diff_info_commits[changeset.node()] = info


class MercurialReviewRequest(BaseReviewRequest):
    def __init__(self, root, repo, changeset,
                 submitter, differ, web, topic):
        super(MercurialReviewRequest, self).__init__(root,
                                                     repo,
                                                     changeset,
                                                     submitter,
                                                     differ,
                                                     web,
                                                     topic)

    def approved(self):
        approved = super(MercurialReviewRequest, self).approved()
        if approved:
            for rev in self._changesets:
                if rev.phase() == 'draft':
                    self._failure = 'Phase of changeset(s) is "draft"'
                    return False
        return approved

    def _commit_id_data(self):
        content = super(MercurialReviewRequest, self)._commit_id_data()

        if self._topic is None:
            graft = self._changesets[0].graft(False)
            if graft:
                if six.PY2:
                    content.append(graft)
                else:
                    content.append(bytes(graft, 'ascii'))

        return content

    def _update_attachments(self, uploaded):
        stored_hashes = {}
        if 'file_hashes' in self.request.extra_data:
            stored_hashes = json.loads(self.request.extra_data['file_hashes'])

        a = self.request.get_file_attachments(only_fields='caption,'
                                              'attachment_history_id',
                                              only_links='delete')
        hashes = {}
        existing = {}
        for entry in a.all_items:
            existing[entry['caption']] = entry

        def modified(filename):
            d = self._changesets[0].diffstat()
            return filename in d and d[filename] != '0'

        def handle_upload(f):
            e = existing.get(f)
            history = e['attachment_history_id'] if e else None
            content = self._changesets[0].file(f)
            hashes[f] = self.diff_info.getRawHash(content)
            if f not in stored_hashes or hashes[f] != stored_hashes[f]:
                a.upload_attachment(f, content, f, history)

        mods = self._changesets[0].files('{file_mods|json}')
        adds = self._changesets[0].files('{file_adds|json}')
        foundAttachments = []
        uploaded = [x.dest_file for x in uploaded]
        for entry in set(adds + mods):
            if (
                self.regexUpload.match(entry)
                    and entry not in uploaded
            ):
                foundAttachments.append(entry)

        if len(foundAttachments) > 0:
            files = self._changesets[0].files()  # let's detect deleted files
            copies = self._changesets[0].files('{file_copies|json}')
            for e in foundAttachments:
                if e not in files:
                    continue
                if e in copies and not modified(e):
                    continue
                handle_upload(e)

        for entry in stored_hashes:
            if entry not in hashes and entry in existing:
                existing[entry].delete()

        return json.dumps(hashes)

    def _check_and_set_fake_diff(self, diff_info, changesets):
        """Generate the diff if it has been changed.

        Fake a diff if the diff cannot be created!
        This will happend for the following commands:
        - A commit for new branch: "hg branch" and "hg push --new-branch"
        - A commit to close a branch: "hg commit --close-branch"
        """
        if diff_info.getDiff() is None:
            content = []
            for changeset in changesets:
                for data in changeset.raw_data():
                    content.append(b'+%s' % data)

            fake_diff = FAKE_DIFF_TEMPL % (len(content) + 5,
                                           b'\n'.join(content))
            diff_info.setDiff(fake_diff)


class GitReviewRequest(BaseReviewRequest):
    def __init__(self, root, repo, changeset,
                 submitter, differ, web, topic):
        super(GitReviewRequest, self).__init__(root,
                                               repo,
                                               changeset,
                                               submitter,
                                               differ,
                                               web,
                                               topic)

    def approved(self):
        approved = super(GitReviewRequest, self).approved()
        if approved:
            for rev in self._changesets:
                if rev.hasDangling():
                    self._failure = ('The merge has dangling changesets: %s'
                                     % ','.join(rev.merges(nodes=True)))
                    return False
        return approved

    def _should_skip(self, rev):
        if rev.isDangling():
            return 'Dangling changeset on branch "%s"' % rev.branch()
        return super(GitReviewRequest, self)._should_skip(rev)

    def _info_template(self):
        if self.request.created_with_history:
            return super(GitReviewRequest, self)._info_template()
        else:
            return ('```{author} ({date}) [{node}] '
                    '[{branch}]'
                    '```\n\n{desc}')

    def _generate_diff(self, parent, node, base):
        # git hash-object -t tree /dev/null
        initialCommit = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'

        if base == '0000000000000000000000000000000000000000':
            base = initialCommit

        if parent is None:
            parent = initialCommit

        return super(GitReviewRequest, self)._generate_diff(parent,
                                                            node,
                                                            base)


class MercurialGitHookCmd(BaseCommand):
    """Helper to parse configuration from .reviewboardrc file."""

    name = 'MercurialGitHook'
    needs_api = True
    option_list = [
        BaseCommand.server_options,
        BaseCommand.repository_options,
    ]

    def __init__(self):
        super(MercurialGitHookCmd, self).__init__()
        parser = self.create_arg_parser([])
        self.options = parser.parse_args([])


class BaseRevision(object):
    def __init__(self):
        self._summary = None
        self._topic = None

    def summary(self):
        if self._summary is None:
            self._summary = self.desc().splitlines()[0].strip()
            if len(self._summary) > 150:
                self._summary = self._summary[0:150] + ' ...'
        return self._summary

    def mail(self):
        mail = re.search(r'<(.*)>', self.author())
        return mail.group(1).strip() if mail and mail.group(1) else None

    def authorName(self):
        return re.sub(r'<.*>', '', self.author()).strip()

    def topic(self):
        if self._topic is None:
            matches = re.findall(r'^topic:([a-z|A-Z|0-9|/| ]+)',
                                 self.desc(), re.MULTILINE)
            if len(matches) > 0:
                self._topic = matches[-1].strip()
            else:
                self._topic = ""

        return None if self._topic == "" else self._topic


class MercurialRevision(BaseRevision):
    """Class to represent information of changeset."""
    @staticmethod
    def fetch_base(current, changes):
        for change in changes:
            if current['parents'][0] == change['node']:
                return MercurialRevision.fetch_base(change, changes)
        return current['parents'][0]

    @staticmethod
    def fetch(revset, fetch_base=False):
        changes = execute([HG, 'log', '--debug',
                           '--config', 'ui.message-output=stderr',
                           '-r', revset, '--template', 'json'],
                          with_errors=False,
                          return_errors=False)

        changes = json.loads(changes)
        result = []
        for entry in changes:
            if fetch_base:
                base = MercurialRevision.fetch_base(entry, changes)
            else:
                base = None
            result.append(MercurialRevision(entry, base))
        return result

    def __init__(self, json, base):
        super(MercurialRevision, self).__init__()
        self.json = json
        self._date = None
        self._merges = None
        self._diffstat = None
        self._graft_source = None
        self._raw_data = None
        self._base = base

    def topic(self):
        if 'extra' in self.json and 'topic' in self.json['extra']:
            return self.json['extra']['topic']

        return super(MercurialRevision, self).topic()

    def graft(self, short=True):
        if self._graft_source is None:
            self._graft_source = ''

            if 'extra' in self.json:
                if 'source' in self.json['extra']:
                    self._graft_source = self.json['extra']['source']

        if len(self._graft_source) > 0:
            return self._graft_source[:12] if short else self._graft_source

        return None

    def base(self):
        return self._base

    def parent(self, short=False):
        p = self.json['parents'][0]
        return p[:12] if short else p

    def node(self, short=False):
        n = self.json['node']
        return n[:12] if short else n

    def branch(self):
        return self.json['branch']

    def author(self):
        return self.json['user']

    def phase(self):
        return self.json['phase']

    def date(self):
        if self._date is None:
            class Offset(dt.tzinfo):
                def __init__(self, offset):
                    self._offset = dt.timedelta(seconds=offset)

                def utcoffset(self, dt):
                    return self._offset

            d = self.json['date']
            offset = d[1] * -1
            if sys.hexversion < 0x030b00f0:
                d = dt.datetime.utcfromtimestamp(d[0] + offset)
            else:
                d = dt.datetime.fromtimestamp(d[0] + offset, dt.UTC)
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

    def isMerge(self):
        return len(self.json['parents']) == 2

    def merges(self):
        """Get all changeset of this merge change.

        If this is a merge changeset we can fetch
        all changesets that will be merged.
        """
        if self.isMerge() and self._merges is None:
            p = self.json['parents']
            revset = 'ancestors({p2}) and ' \
                     '(children(ancestor(ancestor({p1}, {p2}),' \
                     '{node}))::' \
                     '{node})'.format(p1=p[0], p2=p[1], node=self.node())
            self._merges = MercurialRevision.fetch(revset)

        return self._merges

    def raw_data(self):
        if self._raw_data is None:
            j = self.json
            content = []
            content.append('changeset: %s' % j['node'])
            content.append('parents:   %s' % json.dumps(j['parents']))
            content.append('user:      %s' % j['user'])
            content.append('date:      %s' % self.date())
            content.append('branch:    %s' % j['branch'])
            content.append('extra:     %s' % json.dumps(j['extra']))

            if six.PY2:
                self._raw_data = content
            else:
                self._raw_data = []
                for line in content:
                    self._raw_data.append(bytes(line, 'utf-8'))

        return self._raw_data


class GitRevision(BaseRevision):
    """Class to represent information of changeset."""

    @staticmethod
    def fetch_known_branches(rev):
        output = execute(['git', 'branch', '--contains', rev])
        branches = []
        for branch in output.splitlines():
            branches.append(branch.replace('*', '').strip())
        return branches

    @staticmethod
    def fetch_raw(node, base, skipKnown=True):
        if node == '0000000000000000000000000000000000000000':
            return []

        if base == '0000000000000000000000000000000000000000':
            rev = node
        else:
            rev = '%s..%s' % (base, node)
        changes = execute(['git', 'rev-list', rev]).splitlines()
        changes.reverse()

        if skipKnown:
            def isKnown(rev):
                return len(GitRevision.fetch_known_branches(rev)) > 0
            changes[:] = [x for x in changes if not isKnown(x)]
        return changes

    @staticmethod
    def fetch(node, base, refs=None, skipKnown=True):
        changes = GitRevision.fetch_raw(node, base, skipKnown)
        result = []
        for entry in changes:
            result.append(GitRevision(entry, refs, base))
        return result

    def __init__(self, hashnode, refs, base):
        super(GitRevision, self).__init__()
        self._hash = hashnode
        self._refs = self._fetchRefs(refs)
        self._base = base
        self._merges = None
        self._has_dangling = None
        self._is_dangling = False

        pretty = '--pretty=format:%aI#%P#%GT#%G?#%GP#%an <%ae>#%B'
        data = execute(['git', 'log', '-1', self._hash, pretty])
        data = data.split('#', 6)
        self._date = data[0].replace('T', ' ')
        self._parent = data[1].split()
        self._sign_trust = data[2]
        self._sign_verify = data[3]
        self._sign_id = data[4]
        self._user = data[5]
        self._desc = data[6]

    def _fetchRefs(self, refs):
        if refs:
            refs = re.sub(r'^refs/', '', refs)
            refs = re.sub(r'^heads/', '', refs)
        return refs

    def signTrust(self):
        return self._sign_trust

    def signVerify(self):
        return self._sign_verify

    def signId(self):
        return self._sign_id

    def graft(self):
        return None

    def base(self):
        return self._base

    def parent(self, idx=0):
        return self._parent[idx] if idx < len(self._parent) else None

    def node(self, short=False):
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
        entry = '%s:%s' % (self.node(), filename)
        return execute(['git', 'show', entry])

    def dangle(self):
        self._is_dangling = True

    def isDangling(self):
        return self._is_dangling

    def hasDangling(self):
        if self._has_dangling is None:
            self._has_dangling = (
                self.isMerge() and
                len(GitRevision.fetch_known_branches(self.parent(1))) == 0
            )
        return self._has_dangling

    def isMerge(self):
        return len(self._parent) > 1

    def merges(self, nodes=None):
        """Get all changeset of this merge change.

        If this is a merge changeset we can fetch
        all changesets that will be merged.
        """
        if self.isMerge() and self._merges is None:
            self._merges = GitRevision.fetch(self.node(),
                                             self.parent(),
                                             skipKnown=False)
            self._merges.pop()  # remove merge commit itself
            self._merges.reverse()  # use correct order

        if nodes is None:
            return self._merges
        return [x.node(nodes) for x in self._merges]


class BaseHook(object):
    def __init__(self, name, review_request_class, review_differ_class):
        self.submitter = None
        self.repo_name = None
        self.repo_id = None
        self.root = None
        self.web = None
        self.name = name
        self.review_request_class = review_request_class
        self.review_differ_class = review_differ_class
        self._differ = None
        self._process = True

        e = os.environ
        if 'KALLITHEA_EXTRAS' in e:
            kallithea = json.loads(e['KALLITHEA_EXTRAS'])
            self.repo_name = kallithea['repository']
            if 'default' in kallithea['username']:
                log.error('Anonymous access is not supported')
            else:
                self.submitter = kallithea['username']
        elif 'HEPTAPOD_USERINFO_USERNAME' in e and \
             'HEPTAPOD_PROJECT_PATH' in e and \
             'HEPTAPOD_PROJECT_NAMESPACE_FULL_PATH' in e:
            self.submitter = e['HEPTAPOD_USERINFO_USERNAME']
            self.repo_name = \
                e['HEPTAPOD_PROJECT_NAMESPACE_FULL_PATH'] + '/' + \
                e['HEPTAPOD_PROJECT_PATH']
        elif 'GITEA_REPO_NAME' in e and 'GITEA_PUSHER_NAME' in e and\
             'GITEA_REPO_USER_NAME' in e:
            self.submitter = e['GITEA_PUSHER_NAME']
            self.repo_name = e['GITEA_REPO_USER_NAME'] + '/' + \
                e['GITEA_REPO_NAME']
        elif 'GOGS_REPO_NAME' in e and 'GOGS_AUTH_USER_NAME' in e and\
             'GOGS_REPO_OWNER_NAME' in e:
            self.submitter = e['GOGS_AUTH_USER_NAME']
            self.repo_name = e['GOGS_REPO_OWNER_NAME'] + '/' + \
                e['GOGS_REPO_NAME']
        elif 'GL_USERNAME' in e and 'GL_PROJECT_PATH' in e:
            self.submitter = e['GL_USERNAME']
            self.repo_name = e['GL_PROJECT_PATH']
            self._process = e.get('GL_PROTOCOL') != 'web'
        elif 'HGK_USERNAME' in e and 'HGK_REPOSITORY' in e:
            self.submitter = e['HGK_USERNAME']
            self.repo_name = e['HGK_REPOSITORY']
        elif 'REPO_NAME' in e and 'REMOTE_USER' in e:
            self.submitter = e['REMOTE_USER']
            self.repo_name = e['REPO_NAME']
        elif 'GITHUB_REPO_NAME' in e and 'GITHUB_USER_LOGIN' in e:
            self.submitter = e['GITHUB_USER_LOGIN']
            self.repo_name = e['GITHUB_REPO_NAME']
        else:
            self.submitter = getpass.getuser()

        if self.repo_name:
            self.repo_name = self.repo_name.strip('/')

    def _set_repo_id(self):
        """Set ID of repository."""
        fields = 'path,mirror_path,id,extra_data'

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

    def _init_rbtools(self, cmd):
        """Initialize internal rbtools stuff"""
        server_url = cmd.get_server_url(None, None)

        try:
            api_client, root = cmd.get_api(server_url)
        except Exception:
            log.error('Cannot fetch data from RB (%s). '
                      'Is ALLOWED_HOST correct?',
                      server_url)
            raise

        session = get_authenticated_session(api_client, root,
                                            auth_required=True, num_retries=0)
        if session is None or not session.authenticated:
            raise HookError('Please add an USERNAME and a PASSWORD or '
                            'API_TOKEN to .reviewboardrc')

        return root

    def _set_root(self):
        """Set API root object."""
        cmd = MercurialGitHookCmd()
        try:
            if rbversion >= '3':
                cmd.initialize()
                self.root = cmd.api_root
                global SERVER
                SERVER = cmd.get_capabilities(self.root)
            else:
                self.root = self._init_rbtools(cmd)
        except Exception:
            log.error('Cannot init rbtools...')
            log.info('Trying .reviewboardrc (RBTOOLS_CONFIG_PATH) file "'
                     'in "%s" and "%s"',
                     os.environ.get('HOME'),
                     os.environ.get('RBTOOLS_CONFIG_PATH'))
            raise

        self._differ = self.review_differ_class(self.root, cmd)

    def _check_duplicate(self, req, revreqs):
        """Check if a summary or commit_id is already used during this push.

        Args:
            req
                A review request object.

            revreqs
                All previous review requests.

        Returns:
            Boolean:
            True if summary or commit_id is duplicated, otherwise False.
        """
        return any(
            not r.skippable() and
            (r.summary() == req.summary() or r.commit_id == req.commit_id)
            for r in revreqs
        )

    def _handle_changeset_list(self, pushinfo):
        changesets = self._list_of_incoming(pushinfo)
        log.info('Processing %d changeset(s)...', len(changesets))
        return self._handle_changeset_list_process(changesets)

    def _extract_changeset_topics(self, changesets):
        topicchanges = {}
        nontopicchanges = []
        currentTopic = None
        for changeset in changesets:
            topicOption = OPTIONS.get('TOPIC')
            topic = changeset.topic() if topicOption is None else topicOption
            if topic:
                if currentTopic is None:
                    currentTopic = topic
                elif currentTopic != topic:
                    if topic in topicchanges:
                        raise HookError('Topic is out of order: %s'
                                        % currentTopic)
                    currentTopic = topic

                if currentTopic in topicchanges:
                    topicchanges[currentTopic].append(changeset)
                else:
                    topicchanges[currentTopic] = [changeset]
            else:
                nontopicchanges.append(changeset)

        return (topicchanges, nontopicchanges)

    def _get_changeset_topics(self, changesets):
        if 'USE_TOPICS' in OPTIONS:
            return self._extract_changeset_topics(changesets)
        else:
            return ([], changesets)

    def _handle_changeset_list_process(self, changesets):
        topicchanges, changesets = self._get_changeset_topics(changesets)
        revreqs = []

        for changeset in changesets:
            self._handle_changeset_list_process_request([changeset], revreqs)

        for topic in topicchanges:
            log.info("Use topic '%s' with %d changeset(s)",
                     topic,
                     len(topicchanges[topic]))
            self._handle_changeset_list_process_request(topicchanges[topic],
                                                        revreqs,
                                                        topic)

        return self._handle_approved_review_requests(revreqs)

    def _handle_changeset_list_process_request(self,
                                               changesets,
                                               revreqs,
                                               topic=None):
        request = self.review_request_class(self.root,
                                            self.repo_id,
                                            changesets,
                                            self.submitter,
                                            self._differ,
                                            self.web,
                                            topic)

        if self._check_duplicate(request, revreqs):
            log.info('Ignoring changeset(s) (%s) as it has a '
                     'duplicated commit_id or summary: %s | %s',
                     request.nodes(),
                     request.commit_id,
                     request.summary())
            return 1

        self._handle_review_request(request)
        revreqs.append(request)

    def _handle_approved_review_requests(self, revreqs):
        """Handle approved review requests.

        Args:
            revreqs
                All processed review requests.

        Returns:
            int:
            0 on success, otherwise non-zero.
        """
        idx = None

        for i, r in enumerate(revreqs):
            if not r.approved():
                idx = i
                break

        if idx is None:
            if self._is_multi_head_forbidden() and self._is_multi_head():
                log.error('Multiple heads per branch are forbidden!')
            elif 'DEBUGFAIL' not in OPTIONS:
                for r in revreqs:
                    log.info('Closing review request: %s', r.id())
                    r.close()
                return 0
        elif idx > 0:
            self._log_push_info(revreqs[idx - 1].changesets()[-1])

        return 1

    def _is_multi_head(self):
        return False

    def _is_multi_head_forbidden(self):
        headAllowed = os.environ.get('HOOK_MULTI_HEAD_ALLOWED')
        return headAllowed is None or headAllowed.lower() != "on"

    def _log_push_info(self, changeset):
        log.info('If you want to push the already approved '
                 'changes, you can (probably) execute this:')

    def _handle_review_request(self, request):
        """Handle given review request.

        Args:
            request
                A review request object.
        """
        if request.skippable():
            log.info('Skip changeset(s): %s | %s',
                     request.nodes(), request.failure())
            return

        if request.exists():
            if request.modified():
                if request.sync():
                    log.info('Updated review request (%d) for '
                             'changeset(s): %s',
                             request.id(), request.nodes())
                else:
                    log.info('Skipped update of review request (%d) for '
                             'changeset(s): %s',
                             request.id(), request.nodes())
            else:
                if request.approved():
                    log.info('Found approved review request (%d) for '
                             'changeset(s): %s',
                             request.id(), request.nodes())
                else:
                    log.info('Found unchanged review request (%d) for '
                             'changeset(s): %s | %s', request.id(),
                             request.nodes(), request.failure())
        else:
            if request.sync():
                log.info('Created review request (%d) for '
                         'changeset(s): %s', request.id(), request.nodes())
            else:
                log.info('Skipped creation of review request for '
                         'changeset(s): %s', request.nodes())

    def push_to_reviewboard(self, pushinfo):
        """Run the hook.

        Returns:
            int:
            Return code of execution. 0 on success, otherwise non-zero.
        """
        log.debug('Processing push information: %s', pushinfo)
        if not self._process:
            log.info('Processing skipped...')
            return 1 if 'DEBUGFAIL' in OPTIONS else 0

        log.info('Push as user "%s" to "%s"...',
                 self.submitter, self.repo_name)

        if pushinfo is None or len(pushinfo) == 0:
            raise HookError('Initial information is undefined.')

        if self.submitter is None or self.repo_name is None:
            raise HookError('Cannot detect submitter or repository.')

        self._set_root()
        self._set_repo_id()
        return self._handle_changeset_list(pushinfo)


class MercurialHook(BaseHook):
    """Class to represent a hook for Mercurial repositories."""

    def __init__(self):
        super(MercurialHook, self).__init__('Mercurial',
                                            MercurialReviewRequest,
                                            MercurialDiffer)

        if self.repo_name is None:
            self.repo_name = os.environ['HG_PENDING']

    def _is_multi_head(self):
        heads = MercurialRevision.fetch('head() and not closed()')
        if heads is None:
            raise HookError('Cannot fetch branch heads')

        branches = []
        for head in heads:
            if head.branch() in branches:
                return True
            branches.append(head.branch())

        return False

    def _list_of_incoming(self, node):
        """Return a list of all changesets after (and including) node.

        Assumes that all incoming changeset have subsequent revision numbers.

        Returns:
            list of object:
            The list of MercurialRevision.
        """
        return MercurialRevision.fetch(node + ':', True)

    def _set_repo_id(self):
        r = super(MercurialHook, self)._set_repo_id()
        for path in [r.path, r.mirror_path]:
            if path.startswith('http'):
                self.web = path.rstrip('/') + '/rev/{0}'
                break

    def _log_push_info(self, changeset):
        super(MercurialHook, self)._log_push_info(changeset)
        log.info('hg push -r %s', changeset.node(True))


class GitHook(BaseHook):
    """Class to represent a hook for Git repositories."""

    def __init__(self):
        super(GitHook, self).__init__('Git',
                                      GitReviewRequest,
                                      GitDiffer)
        if self.repo_name is None:
            if os.environ.get('GIT_DIR') == '.':
                self.repo_name = os.getcwd()
                if self.repo_name.endswith('/.git'):
                    self.repo_name = self.repo_name[:-5]
            else:
                self.repo_name = os.environ.get('GIT_DIR')

    def _check_signatures(self, changesets):
        hookSignTrust = os.environ.get('HOOK_SIGNATURE_TRUST')
        if not hookSignTrust:
            return True

        hookSignTrust = hookSignTrust.strip().split(',')
        log.info('Check signature trust: %s', hookSignTrust)
        for changeset in changesets:
            if (changeset.signTrust() not in hookSignTrust
               or changeset.signVerify() != 'G'):

                log.info('Signature of changeset (%s) invalid. '
                         'Trust: %s | Verify: %s | Sign-ID: %s',
                         changeset.node(),
                         changeset.signTrust(),
                         changeset.signVerify(),
                         changeset.signId())

                return False

        return True

    def _handle_changeset_list_process(self, changesets):
        if not self._check_signatures(changesets):
            return 1

        if len(changesets) > 1:
            mergeIncoming = {}
            for rev in changesets:
                if rev.hasDangling():
                    nodes = rev.merges(nodes=False)
                    if rev.branch() in mergeIncoming:
                        mergeIncoming[rev.branch()].extend(nodes)
                    else:
                        mergeIncoming[rev.branch()] = nodes

            if len(mergeIncoming) > 0:
                def isDangling(rev):
                    return (
                        rev.branch() in mergeIncoming and
                        rev.node() in mergeIncoming[rev.branch()]
                    )
                [x.dangle() for x in changesets if isDangling(x)]

        return super(GitHook, self)._handle_changeset_list_process(changesets)

    def _list_of_incoming(self, lines):
        revs = []
        for line in lines:
            (base, node, ref) = line.split()
            revs.extend(GitRevision.fetch(node, base, ref))
        return revs

    def _set_repo_id(self):
        r = super(GitHook, self)._set_repo_id()
        d = r.extra_data
        if (
            'hosting_url' in d and
            'gitlab_group_name' in d and
            'gitlab_group_repo_name' in d
        ):
            self.web = (d['hosting_url'] + '/' +
                        d['gitlab_group_name'] + '/' +
                        d['gitlab_group_repo_name'] +
                        '/-/commit/{0}')

    def _log_push_info(self, changeset):
        super(GitHook, self)._log_push_info(changeset)
        log.info('git push origin %s:%s',
                 changeset.node(True), changeset.branch())


def process_mercurial_hook(stdin):
    CHG = 'chg'
    if is_exe_in_path(CHG):
        global HG
        os.environ['CHGHG'] = HG
        HG = CHG

    node = os.environ.get('HG_NODE')
    if node is None:
        log.info("Skip Review Board: No HG_NODE found")
        return 1 if 'DEBUGFAIL' in OPTIONS else 0

    return MercurialHook().push_to_reviewboard(node)


def process_git_hook(stdin):
    if stdin is None:
        lines = sys.stdin.readlines()
    elif isinstance(stdin, list):
        lines = stdin
    else:
        lines = stdin.splitlines()

    return GitHook().push_to_reviewboard(lines)


def environment_check():
    if 'DEBUGENV' in OPTIONS:
        e = os.environ
        if os.environ.get('HOOK_ENV_ALLOWED') is not None:
            if KEY_ENV in e:
                e = dict(e)
                del e[KEY_ENV]
            log.info(e)
        else:
            log.info('HOOK_ENV_ALLOWED is not enabled')


def get_logging_level():
    if (
        'DEBUG' in OPTIONS and
            OPTIONS['DEBUG'].lower() in ('true', 'on', '1', '')
    ):
        return logging.DEBUG

    return logging.INFO


def set_options():
    global OPTIONS
    OPTIONS = {}

    GIT_OPT_COUNT = 'GIT_PUSH_OPTION_COUNT'
    if GIT_OPT_COUNT in os.environ:
        optionCount = int(os.environ[GIT_OPT_COUNT])
        for option in range(0, optionCount):
            value = os.environ['GIT_PUSH_OPTION_' + str(option)].split('=', 1)
            OPTIONS[value[0].upper()] = (value[1]
                                         if len(value) > 1
                                         else '')
    else:
        HG_ENV_PREFIX = 'HG_USERVAR_'
        for key, value in six.iteritems(os.environ):
            if key.startswith(HG_ENV_PREFIX):
                OPTIONS[key[len(HG_ENV_PREFIX):]] = value


def set_topic_usage():
    OPTIONS['USE_TOPICS'] = None

    if 'TOPIC' in OPTIONS:
        topic = OPTIONS['TOPIC'].lower()
        if topic in ('on', 'off', ''):
            del OPTIONS['TOPIC']
        if topic == 'off':
            del OPTIONS['USE_TOPICS']

    if 'USE_TOPICS' in OPTIONS and rbversion < '2':
        del OPTIONS['USE_TOPICS']


def set_globals():
    set_options()
    set_topic_usage()


def hook(stdin=None):
    try:
        set_globals()
        logging.basicConfig(format='%(levelname)s: %(message)s',
                            level=get_logging_level())
        environment_check()

        if 'HG_TXNNAME' in os.environ:
            log.debug('Mercurial detected...')
            return process_mercurial_hook(stdin)
        else:
            log.debug('Git detected...')
            return process_git_hook(stdin)

    except Exception as e:
        if log.getEffectiveLevel() == logging.DEBUG:
            log.exception('Backtrace of error: %s' % e)
        else:
            for line in six.text_type(e).splitlines():
                log.error(line)

    return -1


if __name__ == '__main__':
    import sys
    sys.exit(hook())
