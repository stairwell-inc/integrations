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

import { promisify } from './util.js'

// ----------------------------------
// Splunk JS SDK Helpers
// ----------------------------------
// ---------------------
// Process Helpers
// ---------------------
async function update_configuration_file(
  splunk_js_sdk_service,
  configuration_file_name,
  stanza_name,
  properties,
) {
  // Retrieve the accessor used to get a configuration file
  let splunk_js_sdk_service_configurations = splunk_js_sdk_service.configurations(
      {
          // Name space information not provided
      },
  );
  splunk_js_sdk_service_configurations = await promisify(splunk_js_sdk_service_configurations.fetch)();

  // Check for the existence of the configuration file
  let configuration_file_exist = does_configuration_file_exist(
      splunk_js_sdk_service_configurations,
      configuration_file_name,
  );

  // If the configuration file doesn't exist, create it
  if (!configuration_file_exist) {
      await create_configuration_file(
          splunk_js_sdk_service_configurations,
          configuration_file_name,
      );

      // BUG WORKAROUND: re-fetch because the client doesn't do so
      splunk_js_sdk_service_configurations = await promisify(splunk_js_sdk_service_configurations.fetch)();
  }

  // Retrieves the configuration file accessor
  let configuration_file_accessor = get_configuration_file(
      splunk_js_sdk_service_configurations,
      configuration_file_name,
  );
  configuration_file_accessor = await promisify(configuration_file_accessor.fetch)();

  // Checks to see if the stanza where the inputs will be
  // stored exist
  let stanza_exist = does_stanza_exist(
      configuration_file_accessor,
      stanza_name,
  );

  // If the configuration stanza doesn't exist, create it
  if (!stanza_exist) {
      await create_stanza(configuration_file_accessor, stanza_name);
  }
  // Need to update the information after the creation of the stanza
  configuration_file_accessor = await promisify(configuration_file_accessor.fetch)();

  // Retrieves the configuration stanza accessor
  let configuration_stanza_accessor = get_configuration_file_stanza(
      configuration_file_accessor,
      stanza_name,
  );
  configuration_stanza_accessor = await promisify(configuration_stanza_accessor.fetch)();

  // We don't care if the stanza property does or doesn't exist
  // This is because we can use the
  // configurationStanza.update() function to create and
  // change the information of a property
  await update_stanza_properties(
      configuration_stanza_accessor,
      properties,
  );
};

function create_configuration_file(
  configurations_accessor,
  configuration_file_name,
) {
  return promisify(configurations_accessor.create)(configuration_file_name);
};

// ---------------------
// Existence Functions
// ---------------------
function does_configuration_file_exist(
  configurations_accessor,
  configuration_file_name,
) {
  let was_configuration_file_found = false;

  const configuration_files_found = configurations_accessor.list();
  for (let index = 0; index < configuration_files_found.length; index++) {
      const configuration_file_name_found =
          configuration_files_found[index].name;
      if (configuration_file_name_found === configuration_file_name) {
          was_configuration_file_found = true;
          break;
      }
  }

  return was_configuration_file_found;
};

function does_stanza_exist(
  configuration_file_accessor,
  stanza_name,
) {
  let was_stanza_found = false;

  const stanzas_found = configuration_file_accessor.list();
  for (let index = 0; index < stanzas_found.length; index++) {
      const stanza_found = stanzas_found[index].name;
      if (stanza_found === stanza_name) {
          was_stanza_found = true;
          break;
      }
  }

  return was_stanza_found;
};

function does_stanza_property_exist(
  configuration_stanza_accessor,
  property_name,
) {
  let was_property_found = false;

  for (const [key, value] of Object.entries(
      configuration_stanza_accessor.properties(),
  )) {
      if (key === property_name) {
          was_property_found = true;
          break;
      }
  }

  return was_property_found;
};

// ---------------------
// Retrieval Functions
// ---------------------
function get_configuration_file(
  configurations_accessor,
  configuration_file_name,
) {
  const configuration_file_accessor = configurations_accessor.item(
      configuration_file_name,
      {
          // Name space information not provided
      },
  );

  return configuration_file_accessor;
};

function get_configuration_file_stanza(
  configuration_file_accessor,
  configuration_stanza_name,
) {
  const configuration_stanza_accessor = configuration_file_accessor.item(
      configuration_stanza_name,
      {
          // Name space information not provided
      },
  );

  return configuration_stanza_accessor;
};

function get_configuration_file_stanza_property(
  configuration_file_accessor,
  configuration_file_name,
) {
  return null;
};

function create_stanza(
  configuration_file_accessor,
  new_stanza_name,
) {
  return promisify(configuration_file_accessor.create)(new_stanza_name);
};

function update_stanza_properties(
  configuration_stanza_accessor,
  new_stanza_properties,
) {
  return promisify(configuration_stanza_accessor.update)(new_stanza_properties);
};

export {
  update_configuration_file,
}
