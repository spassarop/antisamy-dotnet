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

using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using OWASP.AntiSamy.Exceptions;
using OWASP.AntiSamy.Html.Model;
using OWASP.AntiSamy.Html.Util;
using Attribute = OWASP.AntiSamy.Html.Model.Attribute;
using Tag = OWASP.AntiSamy.Html.Model.Tag;

namespace OWASP.AntiSamy.Html
{
    /// <summary>
    /// Holds the model for our policy engine.
    /// </summary>
    public class Policy
    {
        public static int DEFAULT_MAX_INPUT_SIZE = 100_000;
        private const string DEFAULT_POLICY_URI = "Resources/OWASP.AntiSamy.xml";
        private const string DEFAULT_ONINVALID = "removeAttribute";

        private readonly Dictionary<string, string> commonRegularExpressions;
        private readonly Dictionary<string, Attribute> commonAttributes;
        private readonly Dictionary<string, Tag> tagRules;
        private readonly Dictionary<string, Property> cssRules;
        private readonly Dictionary<string, string> directives;
        private readonly Dictionary<string, Attribute> globalAttributes;

        /// <summary> Load the policy from an XML file.</summary>
        /// <param name="file">Load a policy from the File object.</param>
        /// <exception cref="PolicyException"></exception>
        private Policy(FileInfo file)
            : this(file.FullName)
        {
        }

        /// <summary> Load the policy from an XML file.</summary>
        /// <param name="filename">Load a policy from the filename specified.</param>
        /// <exception cref="PolicyException"></exception>
        private Policy(string filename)
        {
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(filename);

                XmlNode commonRegularExpressionListNode = doc.GetElementsByTagName("common-regexps")[0];
                commonRegularExpressions = ParseCommonRegExps(commonRegularExpressionListNode);

                XmlNode directiveListNode = doc.GetElementsByTagName("directives")[0];
                directives = ParseDirectives(directiveListNode);

                XmlNode commonAttributeListNode = doc.GetElementsByTagName("common-attributes")[0];
                commonAttributes = ParseCommonAttributes(commonAttributeListNode);

                XmlNode globalAttributesListNode = doc.GetElementsByTagName("global-tag-attributes")[0];
                globalAttributes = ParseGlobalAttributes(globalAttributesListNode);

                XmlNode tagListNode = doc.GetElementsByTagName("tag-rules")[0];
                tagRules = ParseTagRules(tagListNode);

                XmlNode cssListNode = doc.GetElementsByTagName("css-rules")[0];
                cssRules = ParseCssRules(cssListNode);
            }
            catch (Exception ex)
            {
                if (ex is PolicyException)
                {
                    throw;
                }
                else
                {
                    throw new PolicyException($"Problem parsing policy file: {ex.Message}", ex);
                }
            }
        }

        /// <summary> This retrieves a policy based on a default location ("Resources/antisamy.xml")</summary>
        /// <returns> A populated <see cref="Policy"/> object based on the XML policy file located in the default location.</returns>
        /// <exception cref="PolicyException"></exception>
        public static Policy GetInstance() => new Policy(DEFAULT_POLICY_URI);

        /// <summary> This retrieves a policy based on the file name passed in</summary>
        /// <param name="filename">The path to the XML policy file.</param>
        /// <returns> A populated <see cref="Policy"/> object based on the XML policy file located in the location passed in.</returns>
        /// <exception cref="PolicyException"></exception>
        public static Policy GetInstance(string filename) => new Policy(filename);

        /// <summary> This retrieves a policy based on the File object passed in</summary>
        /// <param name="file">A <see cref="FileInfo"/> object which contains the XML policy information.</param>
        /// <returns> A populated <see cref="Policy"/> object based on the XML policy file pointed to by the <c>file</c> parameter.</returns>
        /// <exception cref="PolicyException"></exception>
        public static Policy GetInstance(FileInfo file)
        {
            try
            {
                return new Policy(new FileInfo(file.FullName));
            }
            catch (Exception ex)
            {
                throw new PolicyException($"Problem parsing policy file: {ex.Message}");
            }
        }

        /// <summary>A simple method for returning on of the <common-regexp> entries by name.</summary>
        /// <param name="name">The name of the common-regexp we want to look up.</param>
        /// <returns> A string associated with the common-regexp lookup name specified.</returns>
        public string GetCommonRegularExpressionByName(string name) => name == null ? null : commonRegularExpressions.GetValueOrDefault(name);

        /// <summary> A simple method for returning on of the <global-attribute> entries by name.</summary>
        /// <param name="name">The name of the global-attribute we want to look up.</param>
        /// <returns> An Attribute associated with the global-attribute lookup name specified.</returns>
        public Attribute GetGlobalAttributeByName(string name) => globalAttributes.GetValueOrDefault(name.ToLowerInvariant());

        /// <summary> Return a directive value based on a lookup name.</summary>
        /// <param name="name">The name of the Tag to look up.</param>
        /// <returns> A string object containing the directive associated with the lookup name, or null if none is found.</returns>
        public string GetDirectiveByName(string name) => directives.GetValueOrDefault(name);

        /// <summary> Retrieves a Tag from the Policy.</summary>
        /// <param name="name">The name of the Tag to look up.</param>
        /// <returns> The <see cref="Tag"/> associated with the name specified, or null if none is found.</returns>
        public Tag GetTagByName(string name) => tagRules.GetValueOrDefault(name.ToLowerInvariant());

        /// <summary> Retrieves a CSS Property from the Policy.</summary>
        /// <param name="name">The name of the CSS Property to look up.</param>
        /// <returns> The CSS <see cref="Property"/> associated with the name specified, or null if none is found.</returns>
        public Property GetPropertyByName(string name) => cssRules.GetValueOrDefault(name.ToLowerInvariant());

        /// <summary> A simple method for returning on of the <common-attribute> entries by name.</summary>
        /// <param name="name">The name of the common-attribute we want to look up.</param>
        /// <returns> An <see cref="Attribute"/> associated with the common-attribute lookup name specified.</returns>
        public Attribute GetCommonAttributeByName(string name) => commonAttributes.GetValueOrDefault(name.ToLowerInvariant());

        /// <summary> Go through <directives> section of the policy file.</summary>
        /// <param name="directiveListNode">Top level of <directives></param>
        /// <returns> A Dictionary of directives for validation behavior.</returns>
        private Dictionary<string, string> ParseDirectives(XmlNode directiveListNode)
        {
            var directivesDictionary = new Dictionary<string, string>();

            foreach (XmlElement node in PolicyParserUtil.GetChildrenByTagName(directiveListNode, "directive"))
            {
                string name = XmlUtil.GetAttributeValue(node, "name");
                if (!directivesDictionary.ContainsKey(name))
                {
                    string value = XmlUtil.GetAttributeValue(node, "value");
                    directivesDictionary.Add(name, value);
                }
            }

            return directivesDictionary;
        }

        /// <summary> Go through <global-tag-attributes> section of the policy file.</summary>
        /// <param name="globalAttributeListNode">Top level of <global-tag-attributes></param>
        /// <returns> A Dictionary of global Attributes that need validation for every tag.</returns>
        private Dictionary<string, Attribute> ParseGlobalAttributes(XmlNode globalAttributeListNode)
        {
            var globalAttributesDictionary = new Dictionary<string, Attribute>();

            foreach (XmlElement node in PolicyParserUtil.GetChildrenByTagName(globalAttributeListNode, "attribute"))
            {
                string name = XmlUtil.GetAttributeValue(node, "name");
                Attribute toAdd = GetCommonAttributeByName(name);
                if (toAdd != null)
                {
                    globalAttributesDictionary.Add(name.ToLowerInvariant(), toAdd);
                }
                else
                {
                    throw new PolicyException($"Global attribute '{name}' was not defined in <common-attributes>");
                }
            }

            return globalAttributesDictionary;
        }

        /// <summary> Go through the <common-regexps> section of the policy file.</summary>
        /// <param name="commonRegularExpressionListNode">Top level of <common-regexps></param>
        /// <returns> A List of AntiSamyPattern objects.</returns>
        private Dictionary<string, string> ParseCommonRegExps(XmlNode commonRegularExpressionListNode)
        {
            var commonRegularExpressionsDictionary = new Dictionary<string, string>();

            foreach (XmlElement node in PolicyParserUtil.GetChildrenByTagName(commonRegularExpressionListNode, "regexp"))
            {
                string name = XmlUtil.GetAttributeValue(node, "name");
                if (!commonRegularExpressionsDictionary.ContainsKey(name))
                {
                    string value = XmlUtil.GetAttributeValue(node, "value");
                    commonRegularExpressionsDictionary.Add(name, value);
                }
            }

            return commonRegularExpressionsDictionary;
        }

        /// <summary> Go through the <common-attributes> section of the policy file.</summary>
        /// <param name="commonAttributeListNode">Top level of <common-attributes>.</param>
        /// <returns> A List of Attribute objects.</returns>
        private Dictionary<string, Attribute> ParseCommonAttributes(XmlNode commonAttributeListNode)
        {
            var commonAttributesDictionary = new Dictionary<string, Attribute>();

            foreach (XmlElement node in PolicyParserUtil.GetChildrenByTagName(commonAttributeListNode, "attribute"))
            {
                // TODO: DEFAULT_ONINVALID seems to have been removed from common attributes. Do we need this code?
                string onInvalid = XmlUtil.GetAttributeValue(node, "onInvalid");
                string name = XmlUtil.GetAttributeValue(node, "name");
                var attribute = new Attribute(name)
                {
                    AllowedRegExp = GetAllowedRegexpsForCommonAttributes(node),
                    AllowedValues = PolicyParserUtil.GetAttributeOrValueFromGrandchildren(node, "literal-list", "literal", "value"),
                    Description = XmlUtil.GetAttributeValue(node, "description"),
                    OnInvalid = string.IsNullOrEmpty(onInvalid) ? DEFAULT_ONINVALID : onInvalid,
                };

                commonAttributesDictionary.Add(name.ToLowerInvariant(), attribute);
            }

            return commonAttributesDictionary;
        }

        /// <summary>Get the allowed regular expressions defined in the provided <see cref="XmlElement"/>.</summary>
        /// <param name="node">The node to retrieve the values from.</param>
        /// <returns>A list with the allowed regular expressions.</returns>
        private List<string> GetAllowedRegexpsForCommonAttributes(XmlElement node)
        {
            var allowedList = new List<string>();
            foreach (XmlElement regExNode in PolicyParserUtil.GetGrandchildrenByTagNames(node, "regexp-list", "regexp"))
            {
                string regExName = XmlUtil.GetAttributeValue(regExNode, "name");
                string value = XmlUtil.GetAttributeValue(regExNode, "value");
                string allowedRegEx = string.IsNullOrEmpty(regExName) ? value : GetCommonRegularExpressionByName(regExName).ToString();
                allowedList.Add(allowedRegEx);
            }
            return allowedList;
        }

        /// <summary> Private method for parsing the <tag-rules> from the XML file.</summary>
        /// <param name="root">The root element for <tag-rules></param>
        /// <returns> A Dictionary<string, Tag> containing the rules.</returns>
        /// <exception cref="PolicyException"></exception>
        private Dictionary<string, Tag> ParseTagRules(XmlNode tagAttributeListNode)
        {
            var tagRulesDictionary = new Dictionary<string, Tag>();

            foreach (XmlElement tagNode in PolicyParserUtil.GetChildrenByTagName(tagAttributeListNode, "tag"))
            {
                string tagName = XmlUtil.GetAttributeValue(tagNode, "name");

                var tag = new Tag(tagName)
                {
                    Action = XmlUtil.GetAttributeValue(tagNode, "action"),
                    AllowedAttributes = GetTagAllowedAttributes(tagNode, tagName)
                };

                tagRulesDictionary.Add(tagName.ToLowerInvariant(), tag);
            }

            return tagRulesDictionary;
        }

        /// <summary>Get the allowed attributes defined in the provided tag <see cref="XmlElement"/>.</summary>
        /// <param name="tagNode">The node to retrieve the values from.</param>
        /// <param name="tagName">The name of the tag which has attributes defined.</param>
        /// <returns>A dictionary with the allowed attributes.</returns>
        private Dictionary<string, Attribute> GetTagAllowedAttributes(XmlElement tagNode, string tagName)
        {
            var allowedAttributes = new Dictionary<string, Attribute>();

            foreach (XmlElement attributeNode in PolicyParserUtil.GetChildrenByTagName(tagNode, "attribute"))
            {
                string attributeName = XmlUtil.GetAttributeValue(attributeNode, "name");
                if (!attributeNode.HasChildNodes)
                {
                    /* All they provided was the name, so they must want a common attribute. */
                    Attribute attribute = GetCommonAttributeByName(attributeName);

                    if (attribute != null)
                    {
                        /* If they provide onInvalid/description values here they will override the common values. */
                        string onInvalid = XmlUtil.GetAttributeValue(attributeNode, "onInvalid");
                        string description = XmlUtil.GetAttributeValue(attributeNode, "description");

                        if (!string.IsNullOrEmpty(onInvalid))
                        {
                            attribute.OnInvalid = onInvalid;
                        }
                        if (!string.IsNullOrEmpty(description))
                        {
                            attribute.Description = description;
                        }

                        allowedAttributes.Add(attributeName, attribute.Clone() as Attribute);
                    }
                    else
                    {
                        throw new PolicyException($"Attribute '{XmlUtil.GetAttributeValue(attributeNode, "name")}' was referenced as a common attribute in definition of '{tagName}', but does not exist in <common-attributes>");
                    }
                }
                else
                {
                    /* Custom attribute for this tag */
                    var attribute = new Attribute(XmlUtil.GetAttributeValue(attributeNode, "name"))
                    {
                        AllowedValues = PolicyParserUtil.GetAttributeOrValueFromGrandchildren(attributeNode, "literal-list", "literal", "value"),
                        AllowedRegExp = GetAllowedRegexpsForRules(attributeNode, tagName),
                        Description = XmlUtil.GetAttributeValue(attributeNode, "description"),
                        OnInvalid = XmlUtil.GetAttributeValue(attributeNode, "onInvalid")
                    };

                    allowedAttributes.Add(attributeName, attribute);
                }
            }

            return allowedAttributes;
        }

        /// <summary>Get the allowed regular expressions defined in the provided <see cref="XmlElement"/>. Used for tag rules or CSS rules.</summary>
        /// <param name="node">The node to retrieve the values from.</param>
        /// <param name="elementName">The name of the element which has regular expressions defined.</param>
        /// <returns>A list with the allowed regular expressions.</returns>
        private List<string> GetAllowedRegexpsForRules(XmlElement node, string elementName)
        {
            var allowedList = new List<string>();
            foreach (XmlElement regExNode in PolicyParserUtil.GetGrandchildrenByTagNames(node, "regexp-list", "regexp"))
            {
                string regExName = XmlUtil.GetAttributeValue(regExNode, "name");
                string value = XmlUtil.GetAttributeValue(regExNode, "value");

                /*
                * Look up common regular expression specified by the "name" field. They can put a common
                * name in the "name" field or provide a custom value in the "value" field. They must choose
                * one or the other, not both.
                */
                if (!string.IsNullOrEmpty(regExName))
                {
                    string pattern = GetCommonRegularExpressionByName(regExName);
                    if (pattern != null)
                    {
                        allowedList.Add(pattern);
                    }
                    else
                    {
                        throw new PolicyException($"Regular expression '{regExName}' was referenced as a common regexp in definition of '{elementName}', but does not exist in <common-regexp>.");
                    }
                }
                else if (!string.IsNullOrEmpty(value))
                {
                    // TODO: See if I need to reimplement pattern.compile
                    allowedList.Add(value);
                }
            }
            return allowedList;
        }

        /// <summary> Go through the <css-rules> section of the policy file.</summary>
        /// <param name="cssNodeList">Top level of <css-rules>.</param>
        /// <returns> An List of <see cref="Property"/> objects.</returns>
        private Dictionary<string, Property> ParseCssRules(XmlNode cssNodeList)
        {
            var cssRulesDictionary = new Dictionary<string, Property>();

            foreach (XmlElement propertyNode in PolicyParserUtil.GetChildrenByTagName(cssNodeList, "property"))
            {
                string name = XmlUtil.GetAttributeValue(propertyNode, "name");
                string description = XmlUtil.GetAttributeValue(propertyNode, "description");
                string onInvalid = XmlUtil.GetAttributeValue(propertyNode, "onInvalid");

                var property = new Property(name)
                {
                    Description = description,
                    OnInvalid = string.IsNullOrEmpty(onInvalid) ? DEFAULT_ONINVALID : onInvalid,
                    AllowedRegExp = GetAllowedRegexpsForRules(propertyNode, name),
                    AllowedValues = PolicyParserUtil.GetAttributeOrValueFromGrandchildren(propertyNode, "literal-list", "literal", "value"),
                    ShorthandRefs = PolicyParserUtil.GetAttributeOrValueFromGrandchildren(propertyNode, "shorthand-list", "shorthand", "name"),
                };

                cssRulesDictionary.Add(name.ToLowerInvariant(), property);
            }

            return cssRulesDictionary;
        }
    }
}
