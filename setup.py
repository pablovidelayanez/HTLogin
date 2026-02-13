from setuptools import setup, find_packages
import os

readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
long_description = ""
if os.path.exists(readme_path):
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()

setup(
    name='htlogin',
    version='1.0.0',
    description='Login Security Testing Tool - Tests web application login pages for bypass vulnerabilities',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='akinerkisa',
    url='https://github.com/akinerkisa/HTLogin',
    packages=find_packages(exclude=['renikApp', 'tests']),
    py_modules=['main'],
    package_data={
        'utils': ['languages.json'],
    },
    include_package_data=True,
    install_requires=[
        'beautifulsoup4>=4.9.0',
        'requests>=2.25.0',
        'urllib3>=1.26.0',
        'tqdm>=4.60.0',
        'cloudscraper>=1.2.71',
        'selenium>=4.15.0',
    ],
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'htlogin=main:main',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: Software Development :: Testing',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    keywords='security testing login bypass sql injection nosql xpath ldap',
)


