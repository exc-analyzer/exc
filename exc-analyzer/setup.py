from setuptools import setup

setup(
    name='exc-analyzer',
    version='1.0.0',
    py_modules=['exc_analyzer'],
    entry_points={
        'console_scripts': [
            'exc = exc_analyzer:main',
        ],
    },
    install_requires=[
        'requests',
    ],
    author='brgkdm',
    description='GitHub repo & user analyzer with secret scanner',
    url='https://github.com/exc-analyzer',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
)
