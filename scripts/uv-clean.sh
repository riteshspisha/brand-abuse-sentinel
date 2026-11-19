#!/bin/sh
# Run uv with only an allow-listed environment and no uv configuration file (B7 U10).
#
#   scripts/uv-clean.sh <uv arguments, including --no-config>
#   scripts/uv-clean.sh --python-install <absolute uv path> python install <arguments>
#
# The build paths create the installation's venv, install its hash-pinned requirements
# and wheel, and build the wheel with the pinned backend (B7 U11) through this script.
# Left to the caller's environment, uv 0.12.20 drops a hash-pinned package on
# UV_EXCLUDE, adds bytecode on UV_COMPILE_BYTECODE or a uv.toml, builds another project
# on UV_PROJECT or UV_WORKING_DIR, installs another platform's wheels on
# _PYTHON_HOST_PLATFORM (exit 0 each time), and the build backend runs with PYTHONPATH,
# or in the interpreter VIRTUAL_ENV or CONDA_PREFIX names, so other code replaces or
# wraps the hash-pinned backend. A list of variables to clear always misses one, so uv
# gets only these, when set:
#
#   PATH, HOME, TMPDIR, XDG_DATA_HOME, XDG_CACHE_HOME  where uv and interpreters live
#   UV_OFFLINE, UV_CACHE_DIR      the release build: offline, from a private copy of the
#                                 pinned cache (B7 U3)
#   UV_LINK_MODE                  set by install.sh (copy, never hardlink)
#   UV_PYTHON_CACHE_DIR           --python-install only (see below)
#   proxy and CA variables        transport only; hashes bind what is installed
#
# The uv arguments must include --no-config, so no uv.toml (user, system or in the
# working directory) applies; otherwise this script refuses to run uv. It uses only
# shell syntax and absolute paths, so, run with `sh`, an exported shell function cannot
# change it.
#
# --python-install is the Python step's form only (scripts/service-account/
# install-python.sh, B7 U16): it runs the given absolute uv path, which that script has
# checked against its pin, instead of looking uv up on PATH (a path containing '=' is
# refused: env(1) would take it for an assignment and run the next argument); the
# arguments must be
# `python install ...`, with no download list, mirror or configuration file; and it alone
# also passes UV_PYTHON_CACHE_DIR, where U3 supplies the Python archive (uv checks a
# cached archive against its built-in checksum). Every other call gets neither.
set -eu
UV=uv
case "${1-}" in
    --python-install)
        case "${2-}" in
            *=*)
                /usr/bin/printf '%s\n' "uv-clean: refusing: the uv path contains '=', which env(1) would read as an assignment" >&2
                exit 1
                ;;
            /*) UV=$2 ;;
            *)
                /usr/bin/printf '%s\n' "uv-clean: refusing: --python-install needs an absolute uv path" >&2
                exit 1
                ;;
        esac
        shift 2
        case "${1-} ${2-}" in
            "python install") ;;
            *)
                /usr/bin/printf '%s\n' "uv-clean: refusing: --python-install runs only uv python install" >&2
                exit 1
                ;;
        esac
        for arg in "$@"; do
            case "$arg" in
                --python-downloads-json-url | --python-downloads-json-url=* | --mirror | \
                    --mirror=* | --pypy-mirror | --pypy-mirror=* | --config-file | \
                    --config-file=*)
                    /usr/bin/printf '%s\n' "uv-clean: refusing: $arg would replace uv's built-in Python downloads" >&2
                    exit 1
                    ;;
            esac
        done
        ;;
    *) unset UV_PYTHON_CACHE_DIR ;;
esac
NO_CONFIG=
for arg in "$@"; do
    case "$arg" in --no-config) NO_CONFIG=1 ;; esac
done
case "$NO_CONFIG" in
    1) ;;
    *)
        /usr/bin/printf '%s\n' "uv-clean: refusing: the uv arguments must include --no-config" >&2
        exit 1
        ;;
esac
exec /usr/bin/env -i \
    ${PATH+"PATH=$PATH"} ${HOME+"HOME=$HOME"} ${TMPDIR+"TMPDIR=$TMPDIR"} \
    ${XDG_DATA_HOME+"XDG_DATA_HOME=$XDG_DATA_HOME"} \
    ${XDG_CACHE_HOME+"XDG_CACHE_HOME=$XDG_CACHE_HOME"} \
    ${UV_OFFLINE+"UV_OFFLINE=$UV_OFFLINE"} ${UV_CACHE_DIR+"UV_CACHE_DIR=$UV_CACHE_DIR"} \
    ${UV_LINK_MODE+"UV_LINK_MODE=$UV_LINK_MODE"} \
    ${UV_PYTHON_CACHE_DIR+"UV_PYTHON_CACHE_DIR=$UV_PYTHON_CACHE_DIR"} \
    ${HTTP_PROXY+"HTTP_PROXY=$HTTP_PROXY"} ${HTTPS_PROXY+"HTTPS_PROXY=$HTTPS_PROXY"} \
    ${NO_PROXY+"NO_PROXY=$NO_PROXY"} ${ALL_PROXY+"ALL_PROXY=$ALL_PROXY"} \
    ${http_proxy+"http_proxy=$http_proxy"} ${https_proxy+"https_proxy=$https_proxy"} \
    ${no_proxy+"no_proxy=$no_proxy"} ${all_proxy+"all_proxy=$all_proxy"} \
    ${SSL_CERT_FILE+"SSL_CERT_FILE=$SSL_CERT_FILE"} ${SSL_CERT_DIR+"SSL_CERT_DIR=$SSL_CERT_DIR"} \
    "$UV" "$@"
