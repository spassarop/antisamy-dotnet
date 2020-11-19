/*
 * Copyright (c) 2020, Sebastián Passaro
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

namespace OWASP.AntiSamy.Html.Util
{
    internal static class DictionaryExtensions
    {
        /// <summary>
        /// Returns the default value of type U if the key does not exist in the dictionary
        /// </summary>
        public static U GetValueOrDefault<T, U>(this Dictionary<T, U> dictionary, T key)
        {
#if NETCORE
            return dictionary.GetValueOrDefault(key)
#else
            return dictionary.ContainsKey(key) ? dictionary[key] : default;
#endif
        }

//        public static U GetValueOrDefault<T, U>(this Dictionary<T, U> dictionary, T key)
//        {
//#if NETCORE
//            return dictionary.GetValueOrDefault(key)
//#else
//            return dictionary.ContainsKey(key) ? dictionary[key] : default;
//#endif
//        }

        /// <summary>
        /// Returns an existing value U for key T, or creates a new instance of type U using the default constructor, 
        /// adds it to the dictionary and returns it.
        /// </summary>
        public static U GetOrInsertNew<T, U>(this Dictionary<T, U> dictionary, T key)
            where U : new()
        {
            if (dictionary.ContainsKey(key))
            {
                return dictionary[key];
            }

            U newObject = new U();
            dictionary[key] = newObject;
            return newObject;
        }
    }
}
