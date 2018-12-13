from setuptools import setup, find_packages

setup(
    name='iot-router',
    version='1.0.0dev',
    description='IoT ip implemenetation on WRT Router',
    url='https://github.com/k4vglitcher/IoT_Security.git',
    author='Julio Melchor',
    author_email='jjm2226@columbia.edu',
    license='MIT',
    classifiers=[
        'Development Status :: 1 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7'
    ],
    packages=['iot-router'],
    setup_requires=['scapy'],
    install_requries =['scapy'],
    package_data = {'database' : ['iot-router/device.db']}
)
