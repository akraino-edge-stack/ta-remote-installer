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
Release:        1%{?dist}
Summary:        Contains components for the remote-installer
Group:          %{_platform_group}
License:        %{_platform_licence}
Source0:        %{name}-%{version}.tar.gz
Vendor:         %{_platform_vendor}

BuildArch:      noarch

# BuildRequires:  docker

%description
Contains components for the remote-installer

%prep

%build
docker build \
  --network=host \
  --no-cache \
  --force-rm \
  --build-arg HTTP_PROXY="${http_proxy}" \
  --build-arg HTTPS_PROXY="${https_proxy}" \
  --build-arg NO_PROXY="${no_proxy}" \
  --build-arg http_proxy="${http_proxy}" \
  --build-arg https_proxy="${https_proxy}" \
  --build-arg no_proxy="${no_proxy}" \
  --tag remote-installer \
  --file docker-build/remote-installer/Dockerfile .

# Here hould be some registry but it should be handled by a Jenkis job
docker image save remote-installer >remote-installer-image.tar

%files
