#!/bin/bash

read_arg() {
    # $1 = arg name
    # $2 = arg value
    # $3 = arg parameter
    local rematch='^[^=]*=(.*)$'
    if [[ $2 =~ $rematch ]]; then
        read -r "$1" <<< "${BASH_REMATCH[1]}"
    else
        read -r "$1" <<< "$3"
        # There is no way to shift our callers args, so
        # return 1 to indicate they should do it instead.
        return 1
    fi
}

if type -p podman &>/dev/null; then
    # Using podman
    DOCKER_CMD="podman"
    # Docker is actually implemented by podman, and its OCI output
    # is incompatible with some of the dockerd instances on GitLab
    # CI runners.
    export BUILDAH_FORMAT=docker
elif getent group docker | grep -q "\b${USER}\b"; then
    DOCKER_CMD="docker"
else
    DOCKER_CMD="sudo docker"
fi

set -e

branch=""
version=""
build=0
run=0
push=0
list=0
print_help=0
no_login=0

while (($# > 0)); do
    case "${1%%=*}" in
        build) build=1;;
        run) run=1;;
        push) push=1;;
        list) list=1;;
        help) print_help=1;;
        --branch|-b) read_arg branch "$@" || shift;;
        --version|-v) read_arg version "$@" || shift;;
        --no-login) no_login=1;;
        *) echo -e "\\e[1;31mERROR\\e[0m: Unknown option '$1'"; exit 1;;
    esac
    shift
done

if [ $print_help == 1 ]; then
    echo "$0 - Build and run Docker images"
    echo ""
    echo "Usage: $0 <command> [options] [basename]"
    echo ""
    echo "Available commands"
    echo ""
    echo "  build     - Build Docker image"
    echo "  run       - Run Docker image"
    echo "  push      - Push Docker image to the registry"
    echo "  list      - List available images"
    echo "  help      - This help message"
    echo ""
    exit 0
fi

cd "$(dirname "$0")"

if [ $list == 1 ]; then
    echo "Available Docker images:"
    for f in *.Dockerfile; do
        filename=$( basename -- "$f" )
        basename="${filename%.*}"

        echo -e "  \\e[1;39m$basename\\e[0m"
    done
    exit 0
fi

# We really need to know the branch name after this point
if [[ -z "${branch}" ]]; then
    branch=master
fi

DOCKERFILE="${branch}.Dockerfile"
if [ ! -f "$DOCKERFILE" ]; then
    echo -e "\\e[1;31mERROR\\e[0m: '$DOCKERFILE' not found"
    exit 1
fi

if [ -z "${version}" ]; then
    version="latest"
else
    version="v$version"
fi

TAG="registry.gitlab.gnome.org/gnome/libsecret/${branch}:${version}"

if [ $build == 1 ]; then
    echo -e "\\e[1;32mBUILDING\\e[0m: ${TAG} for branch '${branch}'"
    $DOCKER_CMD build \
        --build-arg HOST_USER_ID="$UID" \
        --tag "${TAG}" \
        --file "$DOCKERFILE" .
    exit $?
fi

if [ $push == 1 ]; then
    echo -e "\\e[1;32mPUSHING\\e[0m: ${TAG} for branch '${branch}'"

    if [ $no_login == 0 ]; then
        $DOCKER_CMD login registry.gitlab.gnome.org
    fi

    $DOCKER_CMD push "${TAG}"
    exit $?
fi

if [ $run == 1 ]; then
    echo -e "\\e[1;32mRUNNING\\e[0m: ${TAG} for branch '${branch}'"
    $DOCKER_CMD run \
        --rm \
        --volume "$(pwd)/..:/home/user/app" \
        --workdir "/home/user/app" \
        --tty \
        --interactive "${TAG}" \
        bash
    exit $?
fi
