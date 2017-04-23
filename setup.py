from distutils.core import setup
import os
import shutil

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "Theia",
    version = "0.0.1",
    author = "Ryan Cote",
    author_email = "minervaconsole@gmail.com",
    description = ("A python remote packet capture and replay utility"),
    license = "Apache 2.0",
    keywords = "security pcap",
    url = "http://github.com/rc1405/theia.git",
    packages=['theia',],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Topic :: Utilities",
        "License :: Apache 2.0",
    ],
    requires=[
        "pyzmq",
        "cryptography",
        "PyYAML",
        "msgpack"
    ],
    data_files = [('/etc/theia', ['conf/agent.yaml','conf/server.yaml'])],
    scripts = ["theia-server.py", "theia-agent.py", "theia-genkey.py"]
)
