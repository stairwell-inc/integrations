// Copyright (C) 2025 Stairwell Inc.

"use strict";

import * as Splunk from './splunk_helpers.js'
import * as Config from './setup_configuration.js'

const SECRET_REALM = 'stairwell_realm'
const SECRET_NAME = 'admin'


export async function perform(splunk_js_sdk, setup_options) {
    var app_name = "stairwell-splunk-app";

    var application_name_space = {
        owner: "nobody",
        app: app_name,
        sharing: "app",
    };

    try {
        const service = Config.create_splunk_js_sdk_service(
            splunk_js_sdk,
            application_name_space,
            );

        let { password, ...properties } = setup_options;

        var storagePasswords = service.storagePasswords();

        let secrets = {
            "password"       : password,
            "userId"         : properties.userId,
            "organizationId" : properties.organizationId
        };
 
        storagePasswords.create({
            name: SECRET_NAME, 
            realm: SECRET_REALM,
            password: JSON.stringify(secrets)
        }, 
            function(err, storagePassword) {
                if (err) 
                    {console.warn(err);}
                else {
                 console.log(storagePassword.properties());
                 }
           });
              
        await Config.complete_setup(service);

        await Config.reload_splunk_app(service, app_name);

        Config.redirect_to_splunk_app_homepage(app_name);
        } catch (error) {

        console.log('Error:', error);
        alert('Error:' + error);
    }
}
