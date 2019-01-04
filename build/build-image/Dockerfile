# Copyright 2018 The OpenShift Authors.
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

# Dockerfile for building in CI

FROM openshift/origin-release:golang-1.10

# Install the golint, use this to check our source for niceness
#RUN go get -u golang.org/x/lint/golint

# Install gomock and mockgen for the mocks used in unit tests
RUN go get -u github.com/golang/mock/gomock
RUN go get -u github.com/golang/mock/mockgen

