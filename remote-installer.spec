# Copyright 2019 Nokia
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Name:           remote-installer
Version:        %{_version}
Release:        3%{?dist}
Summary:        Contains components for the remote-installer
Group:          %{_platform_group}
License:        %{_platform_licence}
Source0:        %{name}-%{version}.tar.gz
Vendor:         %{_platform_vendor}
BuildArch:      %{_arch}

# BuildRequires:  docker

%description
Contains components for the remote-installer

%prep

%build
BASEIMAGE_TAG='centos:7.6.1810'

# For aarch64 use the closest available upstream version
if [ "%{_arch}" = "aarch64" ]; then
    BASEIMAGE_TAG='centos@sha256:df89b0a0b42916b5b31b334fd52d3e396c226ad97dfe772848bdd6b00fb42bf0'
fi

scripts/build.sh -t "${BASEIMAGE_TAG}"

# Here hould be some registry but it should be handled by a Jenkis job
docker image save remote-installer >remote-installer-image.tar

%files
