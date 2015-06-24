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
        public readonly Encoding charEncoding;
        public readonly HMAC hmac;
        public readonly bool resEncAll;
        public readonly EncType resEncoding;
        public readonly TimeSpan lifetime;
        
        public enum EncType { HEXSTRING, BASE64 };

        /// <summary>
        /// Constructor that takes all user settable options. Note that the given
        /// <paramref name="hmac"/> needs to be initialized with your secret key.
        /// </summary>
        /// <param name="charEncoding">The character encoding of the user data
        /// provided to this class's methods.</param>
        /// <param name="hmac">An instance of <see cref="HMAC"/> algorithem
        /// initialized with your secret key.</param>
        /// <param name="resEncAll">Set to <c>False</c> to text-encode just the
        /// hash-mac. Otherwise, set to <c>True</c>, to text-encode a complete
        /// string in the form: "user-data:timestamp:hmac".<br/>
        /// Where "user-data" is a ':' joined string of the user-data elements.
        /// </param>
        /// <param name="resEncoding">Either <c>Base64</c> or <c>Hex String</c>
        /// representation of the (partialy) binary result to returm.</param>
        /// <param name="lifetime">A <c>TimeSpan</c> for the validity of the
        /// created token.</param>
        public SimpleSSO(Encoding charEncoding, HMAC hmac, bool resEncAll, EncType resEncoding, TimeSpan lifetime)
        {
            if (charEncoding == null || hmac == null)
                throw new ArgumentNullException();
            else if (!Enum.IsDefined(typeof(EncType), resEncoding))
                throw new ArgumentOutOfRangeException("resEncoding");
            
            this.charEncoding = charEncoding;
            this.hmac = hmac;
            this.resEncAll = resEncAll;
            this.resEncoding = resEncoding;
            this.lifetime = lifetime;
        }

        /// <summary>
        /// Constructor that creates an instance with these parameters:
        /// <list type="bullet">
        /// <item><description><c>UTF8</c> Encoding,</description></item>
        /// <item><description>an <see cref="HMACSHA256"/> initialized with the
        /// provided <paramref name="key"/>,</description></item>
        /// <item><description>text-encoding the hmac only</description></item>
        /// <item><description>result encoding as hex string</description></item>
        /// <item><description>Five minutes expiration time</description></item>
        /// </list>
        /// </summary>
        /// <param name="key">The secret key phrase.</param>
        public SimpleSSO(string key) : this(
            Encoding.UTF8,
            new HMACSHA256(Encoding.UTF8.GetBytes(key)),
            false,
            EncType.HEXSTRING,
            TimeSpan.FromMinutes(5)) { }

        public string[] CreateTokens(string data, params string[] more)
        {
            // Note: Correctness depens on encoding not using ':',
            //       i.e. if we allow ASCII85 this call may fail.
            return CreateToken(data, more).Split(':');
        }

        public string CreateToken(string data, params string[] more)
        {
            if (String.IsNullOrEmpty(data))
                throw new ArgumentNullException("data");

            string message = CreateMessage(data, more);
            byte[] ba = charEncoding.GetBytes(message);
            byte[] hash = hmac.ComputeHash(ba);
            if (resEncAll)
            {
                return Encode(ConcatenateArrays(ba, hash));
            }
            else
            {
                return message + ":" + Encode(hash);
            }
        }

        public bool IsValid(string token, params string[] more)
        {
            return DecodeData(token, more).Length > 0;
        }

        public string[] DecodeData(string token, params string[] more)
        {
            try
            {
                return Validate(token, more);
            }
            catch (ArgumentException) { }
            catch (CryptographicException) { }
            catch (FormatException) { }
            catch (System.Security.Authentication.InvalidCredentialException) { }
            catch (TimeoutException) { }

            return new string[0];
        }

        public string[] Validate(string token, params string[] more)
        {
            if (String.IsNullOrEmpty(token))
                throw new ArgumentNullException("token");
            else if (more.Length == 1)
                throw new ArgumentException("There may be either one token or three or more tokens.", "more");

            string data = null, 
                   encodedText;
            byte[] ba, hash;
            if (more.Length == 0)
            {
                // Note: Correctness depens on encoding not using ':',
                //       i.e. if we allow ASCII85 this call may fail.
                int pos = token.LastIndexOf(':') + 1;
                if (pos == token.Length)
                {
                    throw new ArgumentException("No hash found in token.", "token");
                }
                else if (pos == 1)
                {
                    throw new ArgumentException("No user data found in token.", "token");
                }
                else if (pos > 1)
                {
                    encodedText = token.Substring(pos);
                    data = token.Substring(0, pos - 1);
                }
                else // pos == 0
                {
                    encodedText = token;
                }
            }
            else
            {
                encodedText = more[more.Length - 1];
                data = ConcatenateStrings(token, more, 0, more.Length - 1);
            }

            if (data == null) // A single encoded token
            {
                ba = Decode(encodedText);
                if (ba.Length <= hmac.HashSize / 8)
                    throw new ArgumentException("Invalid token.", "token");
                hash = new byte[hmac.HashSize / 8];
                Array.Copy(ba, ba.Length - hash.Length, hash, 0, hash.Length);
                Array.Resize(ref ba, ba.Length - hash.Length);
                data = charEncoding.GetString(ba);
            }
            else
            {
                hash = Decode(encodedText);
                if (hash.Length != hmac.HashSize / 8)
                    throw new ArgumentException("Invalid token.", "token");
                ba = charEncoding.GetBytes(data);
            }

            if (!ArrayEquals(hmac.ComputeHash(ba), hash))
                throw new System.Security.Authentication.InvalidCredentialException();
            else if (IsExpired(data))
                throw new TimeoutException("Token expired.");

            return data.Split(':');
        }

        private string CreateMessage(string data, string[] more)
        {
            string ms = Math.Truncate((DateTime.Now - new DateTime(1970, 1, 1)).TotalMilliseconds).ToString();
            return ConcatenateStrings(data, more, 0, more.Length) + ":" + ms;
        }

        private string ConcatenateStrings(string data, string[] more, int startIndex, int count)
        {
            StringBuilder sb = new StringBuilder(data);
            if (more.Length > 0)
                sb.Append(':')
                  .Append(String.Join(":", more, startIndex, count));
            return sb.ToString();
        }

        private byte[] ConcatenateArrays(params byte[][] arrays)
        {
            int pos = 0;
            foreach (var arr in arrays)
            {
                pos += arr.Length;
            }
            byte[] temp = new byte[pos];

            pos = 0;
            foreach (var arr in arrays)
            {
                Array.Copy(arr, 0, temp, pos, arr.Length);
                pos += arr.Length;
            }

            return temp;
        }

        private string Encode(byte[] ba)
        {
            switch (resEncoding)
            {
                case EncType.HEXSTRING:
                    StringBuilder sb = new StringBuilder(ba.Length * 2);
                    foreach (var b in ba)
                    {
                        sb.AppendFormat("{0:x2}", b);
                    }
                    return sb.ToString();

                case EncType.BASE64:
                    return Convert.ToBase64String(ba);

                default:
                    break;
            }
            // We should never get here
            throw new NotSupportedException();
        }

        private byte[] Decode(string encodedText)
        {
            switch (resEncoding)
            {
                case EncType.HEXSTRING:
                    byte[] ba = new byte[encodedText.Length / 2];
                    for (int i = 0; i < ba.Length; i++)
                    {
                        ba[i] = (byte)(HexValue(encodedText[2 * i]) << 4 + HexValue(encodedText[2 * i + 1]));
                    }
                    return ba;

                case EncType.BASE64:
                    return Convert.FromBase64String(encodedText);

                default:
                    break;
            }
            // We should never get here
            throw new NotImplementedException();
        }

        private int HexValue(char c)
        {
            int b = c - '0';
            if (b > 9) b -= 7;
            return b;
        }

        private bool ArrayEquals(byte[] a1, byte[] a2)
        {
            if (ReferenceEquals(a1, a2))
                return true;

            if (a1 == null || a2 == null)
                return false;

            if (a1.Length != a2.Length)
                return false;

            for (int i = 0; i < a1.Length; i++)
                if (a1[i] != a2[i])
                    return false;

            return true;
        }

        private bool IsExpired(string data)
        {
            int pos = data.LastIndexOf(':') + 1;
            int ms = Convert.ToInt32(data.Substring(pos));
            return (DateTime.Now - new DateTime(1970, 1, 1) - lifetime).TotalMilliseconds > ms;
        }
    }
}
