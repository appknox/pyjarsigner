from setuptools import find_packages, setup

setup(
    name='pyjarsigner',
    version='0.2.4',
    url='https://github.com/appknox/pyjarsigner',

    author='Subho Halder',
    author_email='sunny@appknox.com',
    license='GNU Lesser General Public License',

    packages=find_packages(exclude=['tests', 'examples']),
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=['M2Crypto==0.38.0'],
    description="Pure Python3 implementation to sign JAR and APK files",
    long_description="pure Python3 implementation to sign JAR and APK files "
        "which was inspired and borrowed from python-javatools",

    keywords='appknox pyjarsigner jarsigner android apksigner',
    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',

        'License :: OSI Approved :: MIT License',

        'Operating System :: POSIX',
        'Operating System :: MacOS',
        'Operating System :: Unix',

        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',

        'Topic :: Software Development :: Build Tools',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
