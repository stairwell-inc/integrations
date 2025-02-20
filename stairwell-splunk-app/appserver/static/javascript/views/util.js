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

function promisify(fn) {
  console.log("promisify: Don't use this in production! Use a proper promisify library instead.")

  // return a new promisified function
  return (...args) => {
    return new Promise((resolve, reject) => {
      // create a callback that resolves and rejects
      function callback(err, result) {
        if (err) {
          reject(err);
        } else {
          resolve(result);
        }
      }

      args.push(callback)

      // pass the callback into the function
      fn.call(this, ...args);
    })
  }
}

export {
  promisify,
}
