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

using System;
using System.Collections.Generic;
using System.Xml;

namespace OWASP.AntiSamy.Html
{
    /// <summary> 
    /// This class contains the results of a scan.
    /// 
    /// The list of error messages (<see cref="GetErrorMessages"/>) will let the user know
    /// what, if any HTML errors existed, and what, if any, security or
    /// validation-related errors existed, and what was done about them.
    /// </summary>
    public class CleanResults
    {
        private readonly List<string> errorMessages = new List<string>();
        private readonly DateTime startOfScan;
        private readonly DateTime endOfScan;
        private readonly XmlDocumentFragment cleanXMLDocumentFragment;
        private string cleanHTML;

        private const double MILLISECONDS_DENOMINATOR = 1000D;

        public CleanResults()
        {
        }

        public CleanResults(DateTime startOfScan, DateTime endOfScan, string cleanHTML, XmlDocumentFragment XMLDocumentFragment, List<string> errorMessages)
        {
            this.startOfScan = startOfScan;
            this.endOfScan = endOfScan;
            this.cleanXMLDocumentFragment = XMLDocumentFragment;
            this.cleanHTML = cleanHTML;
            this.errorMessages = errorMessages;
        }

        public CleanResults(DateTime date) => startOfScan = date;

        public XmlDocumentFragment GetCleanXMLDocumentFragment() => cleanXMLDocumentFragment;

        public void SetCleanHTML(string cleanHTML) => this.cleanHTML = cleanHTML;

        /// <summary> Return the filtered HTML as a string.</summary>
        /// <returns> A string object which contains the serialized, safe HTML.</returns>
        public string GetCleanHTML() => cleanHTML;

        /// <summary> Return a list of error messages.</summary>
        /// <returns> A <see cref="List{string}"/> object which contains the error messages after a scan.</returns>
        public List<string> GetErrorMessages() => errorMessages;

        /// <summary> Return the time when scan finished.</summary>
        /// <returns> A <see cref="DateTime"/> object indicating the moment the scan finished.</returns>
        public DateTime GetEndOfScan() => endOfScan;

        /// <summary> Return the time when scan started.</summary>
        /// <returns> A <see cref="DateTime"/> object indicating the moment the scan started.</returns>
        public DateTime GetStartOfScan() => startOfScan;

        /// <summary> Return the time elapsed during the scan.</summary>
        /// <returns> A <see langword="double"/> primitive indicating the amount of time elapsed between the beginning and end of the scan in seconds.</returns>
        public double GetScanTime() => (endOfScan.Millisecond - startOfScan.Millisecond) / MILLISECONDS_DENOMINATOR;

        /// <summary> Add an error message to the aggregate list of error messages during filtering.</summary>
        /// <param name="msg">An error message to append to the list of aggregate error messages during filtering.</param>
        public void AddErrorMessage(string msg) => errorMessages.Add(msg);

        /// <summary> Return the number of errors encountered during filtering.</summary>
        public int GetNumberOfErrors() => errorMessages.Count;
    }
}
