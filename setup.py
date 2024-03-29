from setuptools import setup, find_packages

with open("README.md", encoding="utf8") as file:
    read_me_description = file.read()

setup(
    name="oauth-client-lib",
    version="0.1.44",
    author="Sergey Listov",
    author_email="slistov@mail.ru",
    description="OAuth2 client library",
    long_description=read_me_description,
    long_description_content_type="text/markdown",
    url="https://github.com/slistov/oauth_client_lib.git",
    package_dir={"": "src"},
    packages=find_packages(
        where="src",
        include=[
            "oauth_client_lib",
            "oauth_client_lib.*",
        ],
    ),
    install_requires=[
        "pytest",
        "pytest-asyncio",
        "sqlalchemy",
        "fastapi[all]==0.82.0",
        "requests==2.28.1",
        "alembic",
        "psycopg2==2.9.3",
        "python-dotenv==0.21.0",
        "aiohttp==3.8.3",
        "aiofiles==23.1.0",
        "sqlalchemy_json",
        "python-jose",
        "google-api-python-client==2.82.0",
        "google_auth_oauthlib==1.0.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
