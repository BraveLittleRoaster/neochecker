from setuptools import setup

DEPENDENCIES = open('requirements.txt', 'r').read().split('\n')
README = open('README.md', 'r').read()

setup(
    name='neochecker',
    version='1.0.0',
    description='Python library and CLI for checking Neo addresses',
    long_description=README,
    long_description_content_type='text/markdown',
    author='HexOffender',
    author_email='HexOffender_1337@protonmail.com',
    url="http://github.com/",
    packages=['neochecker'],
    entry_points={
        'console_scripts': ['neochecker = neochecker.neochecker:main']
    },
    install_requres=DEPENDENCIES,
    keywords=['security', 'network', 'cryptocurrency'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
