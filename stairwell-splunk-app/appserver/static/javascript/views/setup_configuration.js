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

import * as SplunkHelpers from './splunk_helpers.js'

async function complete_setup(splunk_js_sdk_service) {
  const configuration_file_name = "app";
  const stanza_name = "install";
  let properties_to_update = {
      is_configured: "true",
  };

  await SplunkHelpers.update_configuration_file(
      splunk_js_sdk_service,
      configuration_file_name,
      stanza_name,
      properties_to_update,
  );
};

async function reload_splunk_app(
  splunk_js_sdk_service,
  app_name,
) {
  const splunk_js_sdk_apps = splunk_js_sdk_service.apps();
  await splunk_js_sdk_apps.fetch();

  var current_app = splunk_js_sdk_apps.item(app_name);
  await current_app.fetch();
  await current_app.reload();
};

function redirect_to_splunk_app_homepage(app_name) {
  setTimeout(() => {
  window.location.href = `/app/${app_name}`;
  }, 800); // wait before redirecting
}


const create_splunk_service = (splunk_js_sdk, application_name_space) => 
  new splunk_js_sdk.Service(new splunk_js_sdk.SplunkWebHttp(), application_name_space);

export {
  complete_setup,
  reload_splunk_app,
  redirect_to_splunk_app_homepage,
  create_splunk_service,
}
