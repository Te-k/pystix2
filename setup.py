from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pystix2',
    version='0.0.1',
    description='Simplified and pythonic STIX2 parsing library',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Te-k/pystix2',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='security',
    install_requires=['python-dateutil', 'stringcase'],
    license='MIT',
    packages=['pystix2'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
