// Copyright (C) 2025 Stairwell Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License found in the LICENSE file in the root directory of
// this source tree. Also found at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

"use strict";

var app_name = "stairwell-splunk-app";

require.config({
    paths: {
        myApp: "../app/" + app_name + "/javascript/views/app",
        react: "../app/" + app_name + "/javascript/vendor/react.production.min",
        ReactDOM: "../app/" + app_name + "/javascript/vendor/react-dom.production.min",
    },
    scriptType: "module",
});

require([
    "react", 
    "ReactDOM",
    "myApp",
], function(react, ReactDOM, myApp) {
    ReactDOM.render(myApp, document.getElementById('main_container'));
});
