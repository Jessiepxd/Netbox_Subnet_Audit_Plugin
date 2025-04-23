from setuptools import find_packages, setup

setup(
    name='netbox-subnet-audit-updated',
    version='0.1',
    description='A NetBox plugin for auditing subnets',
    install_requires=[],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
)
