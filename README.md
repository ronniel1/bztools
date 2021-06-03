# bztools

Tools for working with Bugzilla
make sure to install pip package python-bugzilla

## Installation

You can install it by running:

    pip install git+https://github.com/ronniel1/bztools

## Configuration

You can run bztools with either your username & password as well with your bugzilla API key. netrc formatted file.

netrc apikey file example:

    machine bugzilla.redhat.com login apikey password otZjhy1U4nYRlaGUJ2IVR5AIdJCiAy1z6yuGWApr

netrc username password file example:

    machine bugzilla.redhat.com login ronniel1 password my-very-secret-pw

## Usage

    usage: bzclone [-h] [--netrc NETRC | -bup BUGZILLA_USER_PASSWORD] -i BZ_ID
	login options:
      --netrc NETRC         netrc file
      -bup BUGZILLA_USER_PASSWORD, --bugzilla-user-password BUGZILLA_USER_PASSWORD
                            Bugzilla username and password in the format of user:pass

## Development

    git clone https://github.com/ronniel1/bztools
	cd bztools
	pipenv install --dev
	pipenv run pre-commit install -t pre-commit
	pipenv run pre-commit install -t pre-push
