from __future__ import unicode_literals

from reviewboard.extensions.packaging import setup


PACKAGE = "rbExtendedApproval"
VERSION = "0.6.1"

setup(
    name=PACKAGE,
    version=VERSION,
    description='Review Board extension: ExtendedApproval',
    author='Andre Klitzing',
    author_email='aklitzing@gmail.com',
    url='https://github.com/misery/ExtendedApproval',
    packages=[str('extended_approval')],
    install_requires=[
        'reviewboard>=3',
    ],
    entry_points={
        'reviewboard.extensions':
            '%s = extended_approval.extension:ExtendedApproval' % PACKAGE,
    },
    package_data={
        b'extended_approval': [
            'templates/extended_approval/*.txt',
            'templates/extended_approval/*.html',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Framework :: Review Board',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ]
)
