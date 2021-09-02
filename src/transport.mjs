/*
    Kaguya - The opensource instant messaging framework.
    ---
    Copyright 2021 Star Inc.(https://starinc.xyz)

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

import pako from "pako";
import {sha256} from 'js-sha256'
import BigJSON from 'json-bigint'

export default class {
    constructor(apiHost, responseSalt) {
        this.client = new WebSocket(apiHost);
        this.client.onclose = () => console.log('Closed');
        this.responseSalt = responseSalt;
    }

    request(type, data) {
        return this.client.send(
            BigJSON.stringify({type, data})
        );
    }

    setOnMessageHandler(func) {
        this.client.onmessage = (event) => {
            const data = BigJSON.parse(event.data)
            const verifyHash = sha256(
                BigJSON.stringify({
                    data: data.data,
                    salt: this.responseSalt,
                    timestamp: data.timestamp,
                    method: data.method,
                })
            )
            if (verifyHash === data.signature) {
                if (data.data === null) {
                    func(data.data)
                } else {
                    const b64encoded = new Buffer(data.data, 'base64');
                    const compressed = pako.inflate(b64encoded, {to: 'string'});
                    const data = BigJSON.parse(compressed)
                    func(data)
                }
            } else {
                console.error('InvalidSignature')
            }
        }
    }
}
