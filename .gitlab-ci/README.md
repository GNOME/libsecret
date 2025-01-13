# CI support stuff

## Docker image

GitLab CI jobs run in a Docker image, defined here. To update that image
(perhaps to install some more packages):

1. Edit `.gitlab-ci/$BRANCH.Dockerfile` with the changes you want
1. Run `.gitlab-ci/run-docker.sh build --branch=$BRANCH --version=1` to build
   the new image (bump the version from the latest listed for the main branch)
   https://gitlab.gnome.org/GNOME/libsecret/container_registry). If `--branch`
   is not specified, it will use the default branch
1. Run `.gitlab-ci/run-docker.sh push --branch=$BRANCH --version=1` to upload
   the new image to the GNOME GitLab Docker registry
    * If this is the first time you're doing this, you'll need to log into the
      registry
    * If you use 2-factor authentication on your GNOME GitLab account, you'll
      need to [create a personal access token][pat] and use that rather than
      your normal password — the token should have `read_registry` and
      `write_registry` permissions
1. Edit `.gitlab-ci.yml` (in the root of this repository) to use your new
   image

[pat]: https://gitlab.gnome.org/-/profile/personal_access_tokens
