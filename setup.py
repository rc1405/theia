from distutils.core import setup
import os
import shutil

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

try:
    shutil.copytree('conf/','/etc/theia')
    shutil.copyfile('server.py','/usr/local/bin/theia-server.py')
    shutil.copyfile('agent.py','/usr/local/bin/theia-agent.py')
    shutil.copyfile('gen_key.py','/usr/local/bin/theia-genkey.py')
except OSError:
    pass

#try:
    #from Cython.Build import cythonize
#
    #setup(
        #ext_modules = cythonize("theia.py")
    #)
#except ImportError:
if 1 == 1:
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
            "Development Status :: Alpha",
            "Topic :: Utilities",
            "License :: Apache 2.0",
        ],
    )
