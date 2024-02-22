from setuptools import setup, find_packages

setup(
    name='packet-framing',
    version='0.1',
    author="Rauli Kaksonen",
    author_email="rauli.kaksonen@gmail.com",
    description='IP-related packet and frame parsing',
    long_description='Under construction. Research code, not for production use.',
    url='https://gitlab.com/CinCan/framing',
    packages=find_packages(),
    install_requires=[],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
)
