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

// import * as Splunk from './splunk_helpers.js'
import * as Config from './setup_configuration.js'

const SECRET_REALM = 'stairwell_realm'
const SECRET_NAME = 'admin'

export async function perform(splunk_js_sdk, { password, ...properties }) {
    var app_name = "stairwell-splunk-app";

    var application_name_space = {
        owner: "nobody",
        app: app_name,
        sharing: "app",
    };

    try {
        const service = Config.create_splunk_service(
            splunk_js_sdk,
            application_name_space,
            );

        var storagePasswords = service.storagePasswords();

        const secrets = {
            "password"       : password,
            "userId"         : properties.userId,
            "organizationId" : properties.organizationId
        };

        const passwordLookupKey = `${SECRET_REALM}:${SECRET_NAME}`
        const currentPassword = storagePasswords.item(passwordLookupKey);

        function passwordCallback(err, storagePassword) {
            if (err) {
                console.warn(err);
            }
            else {
                console.log(storagePassword.properties());
            }
        }

        if (!currentPassword) {
            storagePasswords.create({
                    name: SECRET_NAME, 
                    realm: SECRET_REALM,
                    password: JSON.stringify(secrets)
                }, 
                passwordCallback);
        } else {
            storagePasswords.update({
                    password: JSON.stringify(secrets)
                }, 
                passwordCallback);
        }

        await Config.complete_setup(service);
        await Config.reload_splunk_app(service, app_name);    
        await Config.redirect_to_splunk_app_homepage(app_name);           
          
    } catch (error) {

        console.log('Error:', error);
        alert('Error:' + error);
    }
}
