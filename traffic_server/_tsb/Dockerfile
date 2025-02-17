# Licensed to the Apache Software Fou:qndation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# SPDX-License-Identifier: Apache-2.0
    # Change BASE_IMAGE to centos when RHEL_VERSION=7
ARG BASE_IMAGE=rockylinux \
    RHEL_VERSION=9
FROM ${BASE_IMAGE}:${RHEL_VERSION} as ats-common-dependencies
ARG RHEL_VERSION=9

MAINTAINER dev@trafficcontrol.apache.org

### Common for all sub-component builds
RUN if [[ ${RHEL_VERSION%%.*} -eq 8 ]]; then \
		yum install -y 'dnf-command(config-manager)'; \
        yum config-manager --set-enabled powertools; \
		
	elif [[ ${RHEL_VERSION%%.*} -eq 9 ]]; then \
        yum install -y 'dnf-command(config-manager)'; \
		yum config-manager --set-enabled crb; \
	else \
		yum install -y deltarpm centos-release-scl-rh; \
		yum-config-manager --enable rhel-server-rhscl-7-rpms; \
	fi && \
	rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-* && \
	rpm --import "https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-${RHEL_VERSION%%.*}" && \
	yum -y clean all && \
	yum -y update ca-certificates && \
	yum -y install \
		git \
		rpm-build \
		rsync \
		epel-release && \
	yum -y clean all

### ats specific requirements
FROM ats-common-dependencies AS build-ats-specific
ARG RHEL_VERSION=9
# Makes RHEL_VERSION accessible to CMD
ENV RHEL_VERSION="$RHEL_VERSION"

RUN if [[ ${RHEL_VERSION%%.*} -eq 8 ]]; then \
		os_pkgs=( \
			brotli \
			brotli-devel \
			curl \
			gcc-toolset-11 \
			gcc-toolset-11-runtime \
			jansson); \
		os_toolset="gcc-toolset-11"; \
	elif [[ ${RHEL_VERSION%%.*} -eq 9 ]]; then \
                os_pkgs=( \
                        brotli \
                        brotli-devel \
                        curl \
                        gcc \
                        jansson \
                        jansson-devel); \
	else \
		os_pkgs=(devtoolset-11 curl jansson jansson-devel); \
	fi \
	&& yum --allowerasing install -y \
		${os_pkgs[*]} \
		libmaxminddb \
		libmaxminddb-devel \
		autoconf \
		automake \
		ed \
		expat-devel \
		flex \
		gcc-c++ \
		glibc-devel \
		hwloc \
		hwloc-devel \
		libcap-devel \
		libcurl-devel \
		libtool \
		libuuid-devel \
		lua-devel \
		luajit-devel \
		make \
		man \
		nano \
		ncurses-devel \
		nmap-ncat \
		openssl \
		openssl-devel \
		pcre \
		pcre-devel \
		perl-Digest-SHA \
		perl-ExtUtils-MakeMaker \
		perl-URI \
		pkgconfig \
		python3 \
		python3-pip \
		sudo \
		tcl-devel \
		zlib \
		zlib-devel \
	&& yum clean all
RUN	pip3 install --user Sphinx
COPY	run.sh /run.sh
COPY	trafficserver.spec /rpmbuilddir/SPECS/trafficserver.spec
RUN	/usr/sbin/useradd -u 176 -r ats -s /sbin/nologin -d /
CMD if [[ ${RHEL_VERSION%%.*} -eq 8 ]]; then \
		os_toolset=gcc-toolset-11; \
		openssl_included='--without_openssl'; \
		scl enable ${os_toolset}; \
	elif [[ ${RHEL_VERSION%%.*} -eq 9 ]]; then \
        openssl_included='--without_openssl'; \
	else \
		os_toolset=devtoolset-11; \
		openssl_included='--with_openssl'; \
		scl enable ${os_toolset}; \
	fi \
	&& set -o pipefail; ./run.sh ${openssl_included} 2>&1 | tee /rpmbuilddir/RPMS/build-trafficserver.log
