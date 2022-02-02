/*
 * Copyright (c) 2013-2022, Kristian Rosenvold, Sebasti�n Passaro
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
using System.Linq;

namespace OWASP.AntiSamy.Html
{
    /// <summary>Uses smart matching to match tags.</summary>
    internal class TagMatcher
    {
        private readonly HashSet<string> allowedLowercase;

        public TagMatcher(List<string> allowedValues)
        {
#if NET5_0
            allowedLowercase = allowedValues.Select(v => v.ToLowerInvariant()).ToHashSet();
#else
            allowedLowercase = new HashSet<string>(allowedValues.Select(v => v.ToLowerInvariant()).ToList());
#endif
        }

        /// <summary>Examines if this tag matches the values in this matcher.
        /// Please note that this is case-insensitive, which is ok for HTML and XHTML, but not really for XML.</summary>
        /// <param name="tagName">The tag name to look for.</param>
        /// <returns><see langword="true"/> if the tag name matches in this matcher.</returns>
        public bool Matches(string tagName) => allowedLowercase.Contains(tagName.ToLowerInvariant());

        public int Size() => allowedLowercase.Count;
    }
}
