from setuptools import setup, find_packages

setup(
    name="pth-injection-demo",
    version="0.0.1",
    description="Looks normal but ships a malicious .pth file",
    packages=find_packages(),
)
