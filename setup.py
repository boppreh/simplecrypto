from distutils.core import setup

setup(
    name='Simplecrypto',
    version=open('CHANGES.txt').read().split()[0],
    author='Lucas Boppre Niehues',
    author_email='lucasboppre@gmail.com',
    packages=['simplecrypto'],
    url='http://pypi.python.org/pypi/Simplecrypto/',
    license='LICENSE.txt',
    description='Simplecrypto',
    long_description=open('README.md').read(),
)