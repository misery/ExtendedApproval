from __future__ import unicode_literals

from reviewboard.extensions.packaging import setup


PACKAGE = "ExtendedApproval"
VERSION = "0.3"

setup(
    name=PACKAGE,
    version=VERSION,
    description="Extension ExtendedApproval",
    author="Andre Klitzing",
    packages=[str('extended_approval')],
    entry_points={
        'reviewboard.extensions':
            '%s = extended_approval.extension:ExtendedApproval' % PACKAGE,
    },
    package_data={
        b'extended_approval': [
            'templates/extended_approval/*.txt',
            'templates/extended_approval/*.html',
        ],
    }
)
