// Copyright (C) 2025 Stairwell Inc.

import * as Setup from "./store_secret.js";

define(["react", "splunkjs/splunk"], function(react, splunk_js_sdk){
  const e = react.createElement;

  class SetupPage extends react.Component {
    constructor(props) {
      super(props);

      this.state = {
        password: '',
        userId: '',
        organizationId: ''
      };

      this.handleChange = this.handleChange.bind(this);
      this.handleSubmit = this.handleSubmit.bind(this);
    }

    handleChange(event) {
      this.setState({ ...this.state, [event.target.name]: event.target.value})
    }

    async handleSubmit(event) {
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
