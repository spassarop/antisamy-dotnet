/*
* Copyright (c) 2008-2020, Jerry Hoff
* 
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
* 
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of OWASP nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

using System.Text;

namespace OWASP.AntiSamy.Html.Util
{
    public class HtmlEntityEncoder
    {
        /// <summary> A helper method for HTML entity-encoding a string value.</summary>
        /// <param name="value">A string containing HTML control characters.</param>
        /// <returns> An HTML-encoded string.</returns>
        public static string HtmlEntityEncode(string value)
        {
            if (value == null)
            {
                return null;
            }

            const int DC4_INT_VALUE = 20;
            const int TILDE_INT_VALUE = 126;

            var buff = new StringBuilder();

            for (int i = 0; i < value.Length; i++)
            {
                char ch = value[i];

                if (ch == '&')
                {
                    buff.Append("&amp;");
                }
                else if (ch == '<')
                {
                    buff.Append("&lt;");
                }
                else if (ch == '>')
                {
                    buff.Append("&gt;");
                }
                else if (char.IsWhiteSpace(ch))
                {
                    buff.Append(ch);
                }
                else if (char.IsLetterOrDigit(ch))
                {
                    buff.Append(ch);
                }
                else if (ch >= DC4_INT_VALUE && ch <= TILDE_INT_VALUE)
                {
                    buff.Append("&#" + (int)ch + ";");
                }
            }

            return buff.ToString();
        }
    }
}
