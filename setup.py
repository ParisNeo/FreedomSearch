from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="freedom_search",
    version="0.1.6",
    author="ParisNeo",
    author_email="parisneoai@gmail.com",
    description="Empower your AI models with ethical, open-source web intelligence",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ParisNeo/FreedomSearch",
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=requirements,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.7",
)