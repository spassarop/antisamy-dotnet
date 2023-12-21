/*
 * Copyright (c) 2023, Sebastián Passaro
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

using System.Globalization;
using System.Resources;
using System.Text.RegularExpressions;
using OWASP.AntiSamy.Html.Scan;

namespace OWASP.AntiSamy.Html.Util
{
    internal static class ErrorMessageUtil
    {
        public static string CurrentCultureName { get; set; }

        /// <summary>A helper method to get error messages from resources and replacing arguments on placeholders.</summary>
        /// <remarks>If the argument count does not match the number of placeholders, an exception will be thrown.</remarks>
        /// <param name="messageKey">The key name to get the message.</param>
        /// <param name="arguments">Additional arguments to place in the formatted message.</param>
        /// <returns>The formatted error message.</returns>
        /// <exception cref="System.ArgumentNullException"/>
        /// <exception cref="System.FormatException"/>
        /// <exception cref="System.InvalidOperationException"/>
        /// <exception cref="MissingManifestResourceException"/>
        /// <exception cref="MissingSatelliteAssemblyException"/>
        public static string GetMessage(string messageKey, params object[] arguments)
        {
            string rawMessage = string.IsNullOrEmpty(CurrentCultureName) ? 
                Properties.Resources.ResourceManager.GetString(messageKey):
                Properties.Resources.ResourceManager.GetString(messageKey, new CultureInfo(CurrentCultureName));

            return string.Format(rawMessage, arguments);
        }

        internal static void SetCulture(string cultureName)
        {
            if (IsValidCultureFormat(cultureName) && IsCultureSupported(cultureName))
            {
                CurrentCultureName = cultureName;
            }
            else
            {
                throw new CultureNotFoundException(string.Format(Constants.ERROR_CULTURE_NOTSUPPORTED, string.Join(", ", Constants.SUPPORTED_LANGUAGES)));
            }
        }

        private static bool IsValidCultureFormat(string cultureName)
        {
            // Enough control for cultures supported today
            return new Regex(@"^[a-z]{2}(-[A-Z]{2})?$", RegexOptions.Compiled).IsMatch(cultureName);
        }

        private static bool IsCultureSupported(string cultureName)
        {
            if (Constants.SUPPORTED_LANGUAGES.Contains(cultureName))
            {
                return true;
            }

            try
            {
                string parentCulture = new CultureInfo(cultureName).Parent.Name;
                return Constants.SUPPORTED_LANGUAGES.Contains(parentCulture);
            }
            catch
            {
                return false;
            }
        }
    }
}
