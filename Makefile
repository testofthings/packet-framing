PYPI_API_KEY = ""

REPO_URL = --repository-url https://test.pypi.org/legacy/

# Default target, test, build and release
# Set REPO_URL to empty string to upload to real PyPi
release: unit-tests
	$(MAKE) release-build
	$(MAKE) release-upload

release-build: upload
	rm -rf build/ dist/ *.egg-info
	python setup.py sdist bdist_wheel

release-upload:
	TWINE_USERNAME="__token__" TWINE_PASSWORD="$(PYPI_API_KEY)" twine upload $(REPO_URL) dist/*

unit-tests:
	python -m pytest tests/
