/*
 * Copyright (c) 2008-2022, Jerry Hoff, Sebastián Passaro
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

using System.IO;
using OWASP.AntiSamy.Html.Scan;

namespace OWASP.AntiSamy.Html
{
    /// <summary> 
    /// This is the only class from which the outside world should be calling. The <c>Scan()</c> method holds
    /// the meat and potatoes of AntiSamy. The file contains a number of ways for <c>Scan()</c>'ing depending
    /// on the accessibility of the policy file.
    /// </summary>
    public class AntiSamy
    {
        private AntiSamyDomScanner Scanner { get; set; }

        /// <remarks> 
        /// The meat and potatoes. The <c>Scan()</c> family of methods are the
        /// only methods the outside world should be calling to invoke AntiSamy.
        /// </remarks>
        /// <summary>This method calls the actual scan using the default policy document (antisamy.xml).</summary>
        /// <param name="taintedHTML">Untrusted HTML which may contain malicious code.</param>
        /// <returns> A <see cref="CleanResults"/> object which contains information about the scan (including the results).</returns>
        /// <exception cref="Exceptions.ScanException"/> 
        /// <exception cref="Exceptions.PolicyException"/>
        public CleanResults Scan(string taintedHTML) => Scan(taintedHTML, Policy.GetInstance());

        /// <summary> This method wraps <c>Scan()</c> using the <see cref="Policy"/> in the specified file.</summary>
        /// <param name="taintedHTML">Untrusted HTML which may contain malicious code.</param>
        /// <param name="filename">Name of the file which contains the policy.</param>
        /// <returns> A <see cref="CleanResults"/> object which contains information about the scan (including the results).</returns>
        /// <exception cref="Exceptions.ScanException"/> 
        /// <exception cref="Exceptions.PolicyException"/>
        public CleanResults Scan(string taintedHTML, string filename) => Scan(taintedHTML, Policy.GetInstance(filename));

        /// <summary> This method wraps <c>Scan()</c> using the <see cref="Policy"/> in the specified file.</summary>
        /// <param name="taintedHTML">Untrusted HTML which may contain malicious code.</param>
        /// <param name="file"><see cref="FileInfo"/> object which contains the policy.</param>
        /// <returns> A <see cref="CleanResults"/> object which contains information about the scan (including the results).</returns>
        /// <exception cref="Exceptions.ScanException"/> 
        /// <exception cref="Exceptions.PolicyException"/>
        public CleanResults Scan(string taintedHTML, FileInfo file) => Scan(taintedHTML, Policy.GetInstance(file));

        /// <summary> This method wraps <c>Scan()</c> using the <see cref="Policy"/> in the specified file.</summary>
        /// <param name="taintedHTML">Untrusted HTML which may contain malicious code.</param>
        /// <param name="stream"><see cref="Stream"/> object which contains the policy.</param>
        /// <returns> A <see cref="CleanResults"/> object which contains information about the scan (including the results).</returns>
        /// <exception cref="Exceptions.ScanException"/> 
        /// <exception cref="Exceptions.PolicyException"/>
        public CleanResults Scan(string taintedHTML, Stream stream) => Scan(taintedHTML, Policy.GetInstance(stream));

        /// <summary> This method wraps the actual <c>Scan()</c> using the <see cref="Policy"/> object passed in.</summary>
        /// <param name="taintedHTML">Untrusted HTML which may contain malicious code.</param>
        /// <param name="policy">Policy to use on the scan.</param>
        /// <returns> A <see cref="CleanResults"/> object which contains information about the scan (including the results).</returns>
        /// <exception cref="Exceptions.ScanException"/> 
        public CleanResults Scan(string taintedHTML, Policy policy)
        {
            /*
            * Go get 'em!
            */
            if (Scanner == null)
            {
                Scanner = new AntiSamyDomScanner(policy);
            }
            else
            {
                Scanner.Policy = policy;
            }

            return Scanner.Scan(taintedHTML);
        }

        /// <summary>Use this method if caller has Streams rather than Strings for I/O.
        /// Useful for cases where the response is very large and we don't validate,
        /// simply encode as bytes are consumed from the stream.</summary>
        /// <param name="reader"><see cref="StreamReader"/>Reader that produces the input, possibly a little at a time.</param>
        /// <param name="writer"><see cref="StreamWriter"/>Writer that receives the cleaned output, possibly a little at a time.</param>
        /// <param name="policy"><see cref="Policy"/> that directs the scan.</param>
        /// <returns><see cref="CleanResults"/> where the cleanHtml is null. If caller wants the clean HTML, it
        /// must capture the writer's contents. When using Streams, caller generally
        /// doesn't want to create a single string containing clean HTML.</returns>
        /// <exception cref="Exceptions.ScanException"/> 
        /// <exception cref="Exceptions.PolicyException"/>
        /// <exception cref="IOException"/>
        /// <exception cref="System.OutOfMemoryException"/>
        /// <exception cref="System.ObjectDisposedException"/>
        /// <exception cref="System.NotSupportedException"/>
        /// <exception cref="System.Text.EncoderFallbackException"/>
        public CleanResults Scan(StreamReader reader, StreamWriter writer, Policy policy)
        {
            CleanResults results = Scan(reader.ReadToEnd(), policy);
            reader.Close();

            foreach (char c in results.GetCleanHtml())
            {
                writer.Write(c);
            }
            writer.Flush();
            writer.BaseStream.Position = 0; // To read from the start later

            results.SetCleanHtml(null);
            return results;
        }

        /// <summary>Sets the culture for AntiSamy error messages.</summary>
        /// <remarks>Will throw an exception if the specified culture is not included in the supported ones.</remarks>
        /// <param name="cultureName">Name of the culture to set. For example: en-US</param>
        /// <exception cref="System.Globalization.CultureNotFoundException"/>
        public void SetCulture(string cultureName)
        {
            Util.ErrorMessageUtil.SetCulture(cultureName);
        }
    }
}
