# Test fixture — NOT malicious, NOT a real package. Do not run.
# Mimics an sdist that executes a shell command while pip is installing it,
# both at setup.py import time and through a cmdclass override.
import os

from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        # Payload slot: a real sample would fetch and run a stage-2 dropper here.
        os.system("echo supply-unchained-sample-1")
        install.run(self)


os.system("echo executed at setup.py import time")

setup(
    name="sample-malicious-setup",
    version="0.0.1",
    cmdclass={"install": PostInstall},
)
