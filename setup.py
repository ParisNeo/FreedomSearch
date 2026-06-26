from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh
                    if line.strip() and not line.startswith("#")]

setup(
    name="freedom_search",
    version="0.4.0",
    author="ParisNeo",
    author_email="parisneoai@gmail.com",
    description="Empower your AI models with ethical, open-source web intelligence",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ParisNeo/FreedomSearch",
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=requirements,
    extras_require={
        "async": ["aiohttp>=3.9", "asyncio-throttle>=1.0.2"],
    },
    package_data={"freedom_search": ["py.typed"]},
    zip_safe=False,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Typing :: Typed",
    ],
    python_requires=">=3.8",
)
