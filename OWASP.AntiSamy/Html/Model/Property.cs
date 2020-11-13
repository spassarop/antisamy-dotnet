/*
 * Copyright (c) 2008-2020, Jerry Hoff, Sebastián Passaro
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

using System.Collections.Generic;

namespace OWASP.AntiSamy.Html.Model
{
    /// <summary> A model for CSS properties and the "rules" they must follow (either literals
    /// or regular expressions) in order to be considered valid.</summary>
    // Author: Jason Li
    internal class Property
    {
        public List<string> AllowedRegExp { get; set; } = new List<string>();
        public List<string> AllowedValues { get; set; } = new List<string>();
        public List<string> ShorthandRefs { get; set; } = new List<string>();
        public string Name { get; set; }
        public string OnInvalid { get; set; }
        public string Description { get; set; }

        public Property(string name) => this.Name = name;

        /// <summary> Add the specified value to the allowed list of valid values.</summary>
        /// <param name="safeValue">The new valid value to add to the list.</param>
        public void AddAllowedValue(string safeValue) => AllowedValues.Add(safeValue);

        /// <summary> Add the specified value to the allowed list of valid regular expressions.</summary>
        /// <param name="safeRegExpValue">The new valid regular expression to add to the list.</param>
        public void AddAllowedRegExp(string safeRegExpValue) => AllowedRegExp.Add(safeRegExpValue);

        /// <summary> Add the specified value to the allowed list of valid shorthand values.</summary>
        /// <param name="shorthandValue">The new valid shorthand value to add to the list.</param>
        public void AddShorthandRef(string shorthandValue) => ShorthandRefs.Add(shorthandValue);
    }
}
