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

'use strict';

import * as Setup from "./store_secret.js";

define(["react", "splunkjs/splunk"], function(react, splunk_js_sdk){
  const e = react.createElement;

  class SetupPage extends react.Component {
    state = {
      password: '',
      userId: '',
      organizationId: ''
    };

    handleChange = (event) => {
      this.setState({ [event.target.name]: event.target.value})
    }

    handleSubmit = async (event) => {
      event.preventDefault();

      await Setup.perform(splunk_js_sdk, this.state)
    }
    
    render() {
      return e("div", null, [
        e("h2", null, "Enter a stairwell authentication code and organization id to complete app setup."),
        e("div", null, [
          e("form", { onSubmit: this.handleSubmit }, [
            e("label", null, [
              "Authentication code ",
              e("input", { type: "text", name: "password", value: this.state.password, onChange: this.handleChange, required: true })
            ]),
            e("label", null, [
              "User Id (Optional) ",
              e("input", { type: "text", name: "userId", value: this.state.userId, onChange: this.handleChange })
            ]),
            e("label", null, [
              "Organization Id ",
              e("input", { type: "text", name: "organizationId", value: this.state.organizationId, onChange: this.handleChange, required: true })
            ]),
            e("input", { type: "submit", value: "Submit" })
          ])
        ])
      ]);
    }
  }

  return e(SetupPage);
});
