from setuptools import setup

setup(
    name='simplecrypto',
    version=open('CHANGES.txt').read().split()[0],
    author='Lucas Boppre Niehues',
    author_email='lucasboppre@gmail.com',
    packages=['simplecrypto'],
    url='https://github.com/boppreh/simplecrypto',
    license='MIT',
    description='Simple cryptographic library for hashing and encrypting',
    keywords = 'simple cryptography symmetric asymmetric hash encrypt decrypt rsa aes sha md5',
    long_description=open('README.rst').read() + '\n\Last Updates\n-------------\n' + open('CHANGES.txt').read(),

    install_requires=[
        'PyCrypto',
    ],

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
