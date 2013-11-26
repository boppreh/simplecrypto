from distutils.core import setup

setup(
    name='simplecrypto',
    version=open('CHANGES.txt').read().split()[0],
    author='Lucas Boppre Niehues',
    author_email='lucasboppre@gmail.com',
    packages=['simplecrypto'],
    url='http://pypi.python.org/pypi/simplecrypto/',
    license='LICENSE.txt',
    description='Simplecrypto',
    long_description=open('README.md').read(),

    install_requires=[
        'PyCrypto',
    ],

    classifiers=[
        'Development Status :: 1 - Planning',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
    ],
)
