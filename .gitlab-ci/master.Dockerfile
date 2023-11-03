FROM fedora:39

RUN dnf update -y \
    && dnf install -y \
           clang-analyzer \
           cppcheck \
           dbus-x11 \
           docbook-style-xsl \
           gettext \
           gi-docgen \
           git \
           glib2-devel \
           gnutls-devel \
           gobject-introspection-devel \
           lcov \
           libasan \
           libubsan \
           libgcrypt-devel \
           libxslt \
           meson \
           python3-dbus \
           python3-gobject \
           redhat-rpm-config \
           swtpm \
           swtpm-tools \
           tpm2-abrmd \
           tpm2-tss-devel \
           vala \
           valgrind-devel \
           pam-devel \
           libpamtest-devel \
           pam_wrapper \
    && dnf clean all

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash -p password user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
