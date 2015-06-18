/***************************************************************************
 * Copyright %CreateDate% Opher Shachar
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **************************************************************************/

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Com.Ladpc.Util.SSO
{
    public class SimpleSSO
    {
        public readonly HMAC hmac;
        public readonly bool tokenOnly;

        public SimpleSSO(HMAC hmac, bool tokenOnly)
        {
            this.hmac = hmac;
            this.tokenOnly = tokenOnly;
        }

        public SimpleSSO(string key, bool tokenOnly) : 
            this(new HMACSHA256(Encoding.Default.GetBytes(key)), tokenOnly) { }

        public SimpleSSO(string key) :
            this(new HMACSHA256(Encoding.Default.GetBytes(key)), false) { }

        public string CreateToken(string Key, params string[] Data)
        {
            string ms = Math.Truncate((DateTime.Now - new DateTime(1970, 1, 1)).TotalMilliseconds).ToString();
            string message = String.Join(":", Data) + ":" + ms;
            byte[] ba = hmac.ComputeHash(Encoding.Default.GetBytes(message));

            if (tokenOnly) {
                // TODO: retern hexstring
            }
            else
            {

            }
        }

    }
}
