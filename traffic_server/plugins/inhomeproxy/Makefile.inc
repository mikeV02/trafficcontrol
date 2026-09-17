#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# Only relevant if you drop this directory into a full ATS source tree
# (e.g. as plugins/inhomeproxy/) and build via the ATS autotools build
# system. If you're building standalone against installed ATS headers
# (the normal case -- see README.md), this file is unused; ignore it.
pkglib_LTLIBRARIES += inhomeproxy/inhomeproxy.la
inhomeproxy_inhomeproxy_la_SOURCES = \
	inhomeproxy/inhomeproxy.cc \
	inhomeproxy/utils.cc \
	inhomeproxy/utils.h
