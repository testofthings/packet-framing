from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='packet-framing',
    version='0.2',
    author="Rauli Kaksonen",
    author_email="rauli.kaksonen@gmail.com",
    description='Protocol packet parsing tool',
    long_description='Protocol packet parsing tool for Tcsfw (https://gitlab.com/CinCan/tcsfw) project',
    url='https://gitlab.com/CinCan/framing',
    packages=find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
