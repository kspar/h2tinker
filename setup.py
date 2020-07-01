import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="h2tinker",
    version="0.1",
    author="Kaspar Papli",
    author_email="kaspar.papli@gmail.com",
    description="Low-level HTTP/2 client library based on scapy for tinkering with HTTP/2 connections",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kspar/h2tinker",
    packages=setuptools.find_packages(),
    install_requires=[
          'scapy>=2.4.3',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
