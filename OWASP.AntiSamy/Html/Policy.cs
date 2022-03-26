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

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Xml;
using System.Xml.Schema;
using OWASP.AntiSamy.Exceptions;
using OWASP.AntiSamy.Html.Model;
using OWASP.AntiSamy.Html.Scan;
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
        static private XmlSchemaSet defaultPolicySchemaSet = null;

        private readonly Dictionary<string, string> commonRegularExpressions;
        private readonly Dictionary<string, Attribute> commonAttributes;
        internal readonly Dictionary<string, Tag> tagRules;
        internal readonly Dictionary<string, Property> cssRules;
        internal readonly Dictionary<string, string> directives;
        private readonly Dictionary<string, Attribute> globalAttributes;
        private readonly Dictionary<string, Attribute> dynamicAttributes;
        private readonly TagMatcher allowedEmptyTagsMatcher;

        /// <summary>Maximum input size for the HTML to read.</summary>
        /// <remarks> If this value is not specified by the policy, the <c>DEFAULT_MAX_INPUT_SIZE</c> is used.</remarks>
        internal protected int MaxInputSize { get; set; }
        /// <summary>Determines if adds the value "nofollow" for "rel" attribute on &lt;a&gt; tags.</summary>
        internal protected bool AddNofollowInAnchors { get; protected set; }
        /// <summary>
        /// Determines if adds the value "noopener noreferrer" for "rel" attribute on &lt;a&gt; tags.
        /// Only impacted if anchor has <c>target="_blank"</c> attrbiute.
        /// </summary>
        internal protected bool AddNoopenerAndNoreferrerInAnchors { get; protected set; }
        /// <summary>Determines if validates the &lt;param&gt; tag as &lt;embed&gt; tag.</summary>
        internal protected bool ValidatesParamAsEmbed { get; set; }
        /// <remarks>Currently not in use.</remarks>
        internal protected bool FormatsOutput { get; set; }
        /// <summary>Determines if HTML output gets trimmed.</summary>
        internal protected bool PreservesSpace { get; set; }
        /// <summary>Avoids prepending prepend the <c>"&lt;?xml ...&gt;"</c> initial tag when using XHTML.</summary>
        internal protected bool OmitsXmlDeclaration { get; set; }
        /// <summary>Avoids prepending prepend the <c>"&lt;!DOCTYPE html ...&gt;"</c> initial tag.</summary>
        internal protected bool OmitsDoctypeDeclaration { get; set; }
        /// <summary>Determines if HTML output gets encoded regarding special characters, like accents.</summary>
        internal protected bool EntityEncodesInternationalCharacters { get; set; }
        /// <summary>Determines if parser uses XHTML.</summary>
        /// <remarks>Explicitly used for CDATA handling when scanning CSS.</remarks>
        internal protected bool UsesXhtml { get; set; }
        /// <summary>Determines if comments are removed from the HTML.</summary>
        internal protected bool PreservesComments { get; set; }
        /// <summary>Determines if style sheets can be embedded/imported to be parsed.</summary>
        internal protected bool EmbedsStyleSheets { get; set; }
        /// <summary>Determines which action to take when encountering unknown HTML tags instead of removing them.</summary>
        internal protected string OnUnknownTagAction { get; set; }
        /// <summary>Determines if dynamic attributes (like data-*) are allowed.</summary>
        internal protected bool AllowsDynamicAttributes { get; set; }
        /// <summary>Determines how much milliseconds to wait when importing syle sheets.</summary>
        /// <remarks> If this value is not specified by the policy, the <c>DEFAULT_CONNECTION_TIMEOUT</c> is used.</remarks>
        internal protected int ConnectionTimeout { get; set; }
        /// <summary>Determines how much milliseconds to wait when importing syle sheets.</summary>
        /// <remarks> If this value is not specified by the policy, the <c>DEFAULT_MAX_STYLESHEET_IMPORTS</c> is used.</remarks>
        internal protected int MaxStyleSheetImports { get; set; }

        /// <summary>Create policy with <see cref="ParseContext"/>.</summary>
        /// <param name="parseContext">Context with all collections to load the new policy.</param>
        protected Policy(ParseContext parseContext)
        {
            commonAttributes = parseContext.commonAttributes;
            commonRegularExpressions = parseContext.commonRegularExpressions;
            cssRules = parseContext.cssRules;
            directives = parseContext.directives;
            dynamicAttributes = parseContext.dynamicAttributes;
            globalAttributes = parseContext.globalAttributes;
            tagRules = parseContext.tagRules;
            allowedEmptyTagsMatcher = new TagMatcher(parseContext.allowedEmptyTags);
        }

        /// <summary>Create policy with full paramterers.</summary>
        /// <param name="old">Old policy to copy from.</param>
        /// <param name="directives">Directives to override.</param>
        /// <param name="tagRules">Tag rules to override.</param>
        /// <param name="cssRules">CSS rules to override.</param>
        protected Policy(Policy old, Dictionary<string, string> directives, Dictionary<string, Tag> tagRules, Dictionary<string, Property> cssRules)
        {
            commonAttributes = old.commonAttributes;
            commonRegularExpressions = old.commonRegularExpressions;
            this.cssRules = cssRules;
            this.directives = directives;
            dynamicAttributes = old.dynamicAttributes;
            globalAttributes = old.globalAttributes;
            this.tagRules = tagRules;
            allowedEmptyTagsMatcher = old.allowedEmptyTagsMatcher;
        }

        /// <summary> This retrieves a policy based on a default location ("AntiSamyPolicyExamples/antisamy.xml") or from the embedded XML.</summary>
        /// <returns> A populated <see cref="Policy"/> object based on the XML policy file located in the default location.</returns>
        /// <exception cref="PolicyException"></exception>
        public static Policy GetInstance()
        {
            try
            {
                return GetInternalPolicyFromFile(Constants.DEFAULT_POLICY_URI);
            }
            catch
            {
                try
                {
                    return GetInternalPolicyFromStream(new MemoryStream(
                        Encoding.UTF8.GetBytes(Properties.Resources.ResourceManager.GetObject(Constants.DEFAULT_POLICY_RESOURCE_KEY) as string)));
                }
                catch (Exception ex)
                {
                    if (ex is PolicyException)
                    {
                        throw;
                    }

                    throw new PolicyException($"Problem loading policy default XML from stream: {ex.Message}", ex);
                }
            }
        }

        /// <summary> This retrieves a policy based on the file name passed in</summary>
        /// <param name="filename">The path to the XML policy file.</param>
        /// <returns> A populated <see cref="Policy"/> object based on the XML policy file located in the location passed in.</returns>
        /// <exception cref="PolicyException"></exception>
        public static Policy GetInstance(string filename) => GetInternalPolicyFromFile(filename);

        /// <summary> This retrieves a policy based on the file object passed in</summary>
        /// <param name="file">A <see cref="FileInfo"/> object which contains the XML policy information.</param>
        /// <returns> A populated <see cref="Policy"/> object based on the XML policy file pointed to by the <c>file</c> parameter.</returns>
        /// <exception cref="PolicyException"></exception>
        public static Policy GetInstance(FileInfo file) => GetInternalPolicyFromFile(file.FullName);

        /// <summary> This retrieves a policy based on the <see cref="Stream"/> object passed in</summary>
        /// <param name="stream">A <see cref="Stream"/> object which contains the XML policy information.</param>
        /// <returns> A populated <see cref="Policy"/> object based on the XML policy file pointed to by the <c>file</c> parameter.</returns>
        /// <exception cref="PolicyException"></exception>
        public static Policy GetInstance(Stream stream) => GetInternalPolicyFromStream(stream);

        internal static string GetPolicyAbsolutePathFromFilename(string filename)
        {
            if (Path.IsPathRooted(filename))
            {
                return filename;
            }
            else
            {
                var location = new Uri(Assembly.GetExecutingAssembly().Location);
                string assemblyDirectory = new FileInfo(location.AbsolutePath).Directory.FullName;
                return Path.Combine(assemblyDirectory, filename);
            }
        }

        private static InternalPolicy GetInternalPolicyFromFile(string filename)
        {
            return new InternalPolicy(GetParseContext(GetXmlDocumentFromFile(filename)));
        }

        private static InternalPolicy GetInternalPolicyFromStream(Stream stream)
        {
            return new InternalPolicy(GetParseContext(GetXmlDocumentFromStream(stream)));
        }

        /// <summary>Creates a copy of this policy with an added/changed directive.</summary>
        /// <param name="name">The directive to add/modify.</param>
        /// <param name="value">The new directive value.</param>
        /// <returns>A clone of the policy with the updated directive</returns>
        public Policy CloneWithDirective(string name, string value)
        {
            var newDirectives = new Dictionary<string, string>(directives);

            if (newDirectives.ContainsKey(name))
            {
                newDirectives[name] = value;
            }
            else
            {
                newDirectives.Add(name, value);
            }

            return new InternalPolicy(this, newDirectives, tagRules, cssRules);
        }

        /// <summary>A simple method for returning one of the &lt;common-regexp&gt; entries by name.</summary>
        /// <param name="name">The name of the common-regexp we want to look up.</param>
        /// <returns> A string associated with the common-regexp lookup name specified.</returns>
        internal string GetCommonRegularExpressionByName(string name) => name == null ? null : commonRegularExpressions.GetValueOrTypeDefault(name);

        /// <summary> A simple method for returning one of the &lt;global-attribute&gt; entries by name.</summary>
        /// <param name="name">The name of the global-attribute we want to look up.</param>
        /// <returns> An Attribute associated with the global-attribute lookup name specified.</returns>
        internal Attribute GetGlobalAttributeByName(string name) => globalAttributes.GetValueOrTypeDefault(name.ToLowerInvariant());

        /// <summary> Return a directive value based on a lookup name.</summary>
        /// <param name="name">The name of the Tag to look up.</param>
        /// <returns> A string object containing the directive associated with the lookup name, or null if none is found.</returns>
        internal string GetDirectiveByName(string name) => directives.GetValueOrTypeDefault(name);

        /// <summary> Retrieves a Tag from the Policy.</summary>
        /// <param name="name">The name of the Tag to look up.</param>
        /// <returns> The <see cref="Tag"/> associated with the name specified, or null if none is found.</returns>
        internal Tag GetTagByName(string name) => tagRules.GetValueOrTypeDefault(name.ToLowerInvariant());

        /// <summary> Retrieves a CSS Property from the Policy.</summary>
        /// <param name="name">The name of the CSS Property to look up.</param>
        /// <returns> The CSS <see cref="Property"/> associated with the name specified, or null if none is found.</returns>
        internal Property GetPropertyByName(string name) => cssRules.GetValueOrTypeDefault(name.ToLowerInvariant());

        /// <summary> A simple method for returning one of the &lt;common-attribute&gt; entries by name.</summary>
        /// <param name="name">The name of the common-attribute we want to look up.</param>
        /// <returns> An <see cref="Attribute"/> associated with the common-attribute lookup name specified.</returns>
        internal Attribute GetCommonAttributeByName(string name) => commonAttributes.GetValueOrTypeDefault(name.ToLowerInvariant());

        /// <summary> Return all the allowed empty tags configured in the Policy.</summary>
        /// <returns> A <see cref="TagMatcher"/> with all the allowed empty tags configured in the policy.</returns>
        internal TagMatcher GetAllowedEmptyTags() => allowedEmptyTagsMatcher;

        /// <summary>A method for returning one of the dynamic &lt;common-attribute&gt; entries by name.</summary>
        /// <param name="name">The name of the dynamic common-attribute we want to look up.</param>
        /// <returns>An <see cref="Attribute"/> associated with the common-attribute lookup name specified, or null if not found.</returns>
        internal Attribute GetDynamicAttributeByName(string name)
        {
            Attribute dynamicAttribute = null;
            string nameLowercase = name.ToLowerInvariant();
            foreach (KeyValuePair<string, Attribute> attributeEntry in dynamicAttributes)
            {
                if (nameLowercase.StartsWith(attributeEntry.Key))
                {
                    dynamicAttribute = attributeEntry.Value;
                    break;
                }
            }
            return dynamicAttribute;
        }

        internal static ParseContext GetParseContext(XmlDocument document)
        {
            var parseContext = new ParseContext();

            // TODO: Here there was supposed to be a check for <include> tags with href attribute to "merge" policies.
            
            ParsePolicy(document, parseContext);
            return parseContext;
        }

        /// <summary>Generates a <see cref="XmlDocument"/> by loading it from a file.</summary>
        /// <param name="filename">The name of the file which contains the policy XML.</param>
        /// <returns>The loaded <see cref="XmlDocument"/>.</returns>
        /// <exception cref="PolicyException"/>
        internal static XmlDocument GetXmlDocumentFromFile(string filename)
        {
            try
            {
                var document = new XmlDocument
                {
                    // Setting this to NULL disables DTDs - Its NOT null by default on 4.5.1 and older, but leaving it anyway.
                    XmlResolver = null
                };

                document.Load(GetPolicyAbsolutePathFromFilename(filename));
                ValidateSchema(document);

                return document;
            }
            catch (Exception ex)
            {
                throw new PolicyException($"Problem loading policy XML from stream: {ex.Message}", ex);
            }
        }

        /// <summary>Generates a <see cref="XmlDocument"/> by loading it from a stream.</summary>
        /// <param name="stream">The <see cref="Stream"/> which contains the policy XML.</param>
        /// <returns>The loaded <see cref="XmlDocument"/>.</returns>
        /// <exception cref="PolicyException"/>
        private static XmlDocument GetXmlDocumentFromStream(Stream stream)
        {
            try
            {
                var document = new XmlDocument
                {
                    // Setting this to NULL disables DTDs - Its NOT null by default on 4.5.1 and older, but leaving it anyway.
                    XmlResolver = null
                };
                document.Load(stream);
                ValidateSchema(document);

                return document;
            }
            catch (Exception ex)
            {
                throw new PolicyException($"Problem loading policy XML from file: {ex.Message}", ex);
            }
        }

        private static void ValidateSchema(XmlDocument document)
        {
            try
            {
                if (defaultPolicySchemaSet == null)
                {
                    Stream xsdStream = new MemoryStream(Encoding.UTF8.GetBytes(
                        Properties.Resources.ResourceManager.GetObject(Constants.DEFAULT_POLICY_SCHEMA_RESOURCE_KEY) as string));
                    defaultPolicySchemaSet = new XmlSchemaSet();
                    defaultPolicySchemaSet.Add("", XmlReader.Create(xsdStream));
                }

                document.Schemas = defaultPolicySchemaSet;
                document.Schemas.Compile();
                document.Validate(PolicySchemaValidationEventHandler);
            }
            catch (Exception ex)
            {
                if (ex is PolicyException)
                {
                    throw;
                }

                throw new PolicyException($"Problem loading policy default XML from stream: {ex.Message}", ex);
            }
        }

        private static void PolicySchemaValidationEventHandler(object sender, ValidationEventArgs e)
        {
            // This event means there was an error/warning validating the schema
            throw new PolicyException(
                $"Problem validating the policy against the XML schema: \"{e.Severity.ToString().ToUpper()}: {e.Message}\"", e.Exception);
        }

        /// <summary>Parse the policy from the provided <see cref="XmlDocument"/>.</summary>
        /// <param name="document">The policy XML.</param>
        /// <param name="parseContext">The <see cref="ParseContext"/> to fill from the policy.</param>
        private static void ParsePolicy(XmlDocument document, ParseContext parseContext)
        {
            parseContext.ResetParametersWhereLastConfigurationWins();

            try
            {
                ParseCommonRegExps(document.GetElementsByTagName("common-regexps").Item(0), parseContext);
                ParseDirectives(document.GetElementsByTagName("directives").Item(0), parseContext);
                ParseCommonAttributes(document.GetElementsByTagName("common-attributes").Item(0), parseContext);
                ParseGlobalAttributes(document.GetElementsByTagName("global-tag-attributes").Item(0), parseContext);
                ParseDynamicAttributes(document.GetElementsByTagName("dynamic-tag-attributes").Item(0), parseContext);
                ParseTagRules(document.GetElementsByTagName("tag-rules").Item(0), parseContext);
                ParseCssRules(document.GetElementsByTagName("css-rules").Item(0), parseContext);
                ParseAllowedEmptyTags(document.GetElementsByTagName("allowed-empty-tags").Item(0), parseContext);
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

        /// <summary> Go through &lt;directives&gt; section of the policy file.</summary>
        /// <param name="directiveListNode">Top level of &lt;directives&gt;</param>
        /// <param name="parseContext">The <see cref="ParseContext"/> containing the directives dictionary to fill.</param>
        private static void ParseDirectives(XmlNode directiveListNode, ParseContext parseContext)
        {
            foreach (XmlElement node in PolicyParserUtil.GetChildrenByTagName(directiveListNode, "directive"))
            {
                string name = XmlUtil.GetAttributeValue(node, "name");
                if (!parseContext.directives.ContainsKey(name))
                {
                    string value = XmlUtil.GetAttributeValue(node, "value");
                    parseContext.directives.Add(name, value);
                }
            }
        }

        /// <summary> Go through &lt;global-tag-attributes&gt; section of the policy file.</summary>
        /// <param name="globalAttributeListNode">Top level of &lt;global-tag-attributes&gt;</param>
        /// <param name="parseContext">The <see cref="ParseContext"/> containing the global attributes dictionary to fill.</param>
        private static void ParseGlobalAttributes(XmlNode globalAttributeListNode, ParseContext parseContext)
        {
            foreach (XmlElement node in PolicyParserUtil.GetChildrenByTagName(globalAttributeListNode, "attribute"))
            {
                string name = XmlUtil.GetAttributeValue(node, "name");
                Attribute toAdd = parseContext.commonAttributes.GetValueOrTypeDefault(name.ToLowerInvariant());
                if (toAdd != null)
                {
                    parseContext.globalAttributes.Add(name.ToLowerInvariant(), toAdd);
                }
                else
                {
                    throw new PolicyException($"Global attribute '{name}' was not defined in <common-attributes>");
                }
            }
        }

        /// <summary> Go through &lt;dynamic-tag-attributes&gt; section of the policy file.</summary>
        /// <param name="dynamicAttributeListNode">Top level of &lt;dynamic-tag-attributes&gt;</param>
        /// <param name="parseContext">The <see cref="ParseContext"/> containing the dynamic attributes dictionary to fill.</param>
        private static void ParseDynamicAttributes(XmlNode dynamicAttributeListNode, ParseContext parseContext)
        {
            foreach (XmlElement node in PolicyParserUtil.GetChildrenByTagName(dynamicAttributeListNode, "attribute"))
            {
                string name = XmlUtil.GetAttributeValue(node, "name");
                Attribute toAdd = parseContext.commonAttributes.GetValueOrTypeDefault(name.ToLowerInvariant());
                if (toAdd != null)
                {
                    string attributeName = name.ToLowerInvariant().Substring(0, name.Length - 1);
                    parseContext.dynamicAttributes.Add(attributeName, toAdd);
                }
                else
                {
                    throw new PolicyException($"Dynamic attribute '{name}' was not defined in <common-attributes>");
                }
            }
        }

        /// <summary> Go through the &lt;common-regexps&gt; section of the policy file.</summary>
        /// <param name="commonRegularExpressionListNode">Top level of &lt;common-regexps&gt;.</param>
        /// <param name="parseContext">The <see cref="ParseContext"/> containing the common regular expressions dictionary to fill.</param>
        private static void ParseCommonRegExps(XmlNode commonRegularExpressionListNode, ParseContext parseContext)
        {
            foreach (XmlElement node in PolicyParserUtil.GetChildrenByTagName(commonRegularExpressionListNode, "regexp"))
            {
                string name = XmlUtil.GetAttributeValue(node, "name");
                if (!parseContext.commonRegularExpressions.ContainsKey(name))
                {
                    string value = XmlUtil.GetAttributeValue(node, "value");
                    parseContext.commonRegularExpressions.Add(name, value);
                }
            }
        }

        /// <summary> Go through the &lt;common-attributes&gt; section of the policy file.</summary>
        /// <param name="commonAttributeListNode">Top level of &lt;common-attributes&gt;.</param>
        /// <param name="parseContext">The <see cref="ParseContext"/> containing the common attributes dictionary to fill.</param>
        private static void ParseCommonAttributes(XmlNode commonAttributeListNode, ParseContext parseContext)
        {
            foreach (XmlElement node in PolicyParserUtil.GetChildrenByTagName(commonAttributeListNode, "attribute"))
            {
                // TODO: Throw exception if onInvalid is defined but is not an expected option?
                string onInvalid = XmlUtil.GetAttributeValue(node, "onInvalid");
                string name = XmlUtil.GetAttributeValue(node, "name");
                var attribute = new Attribute(name)
                {
                    AllowedRegExp = GetAllowedRegexpsForCommonAttributes(node, parseContext),
                    AllowedValues = PolicyParserUtil.GetAttributeOrValueFromGrandchildren(node, "literal-list", "literal", "value"),
                    Description = XmlUtil.GetAttributeValue(node, "description"),
                    OnInvalid = string.IsNullOrEmpty(onInvalid) ? Constants.DEFAULT_ONINVALID : onInvalid,
                };

                parseContext.commonAttributes.Add(name.ToLowerInvariant(), attribute);
            }
        }

        /// <summary>Get the allowed regular expressions defined in the provided <see cref="XmlElement"/>.</summary>
        /// <param name="node">The node to retrieve the values from.</param>
        /// <param name="parseContext">The parse context.</param>
        /// <returns>A list with the allowed regular expressions.</returns>
        private static List<string> GetAllowedRegexpsForCommonAttributes(XmlElement node, ParseContext parseContext)
        {
            var allowedList = new List<string>();
            foreach (XmlElement regExNode in PolicyParserUtil.GetGrandchildrenByTagNames(node, "regexp-list", "regexp"))
            {
                string regExName = XmlUtil.GetAttributeValue(regExNode, "name");
                string value = XmlUtil.GetAttributeValue(regExNode, "value");
                string allowedRegEx;
                if (string.IsNullOrEmpty(regExName))
                {
                    allowedRegEx = value;
                }
                else
                {
                    allowedRegEx = regExName == null ? null : parseContext.commonRegularExpressions.GetValueOrTypeDefault(regExName);
                }
                allowedList.Add(allowedRegEx);
            }
            return allowedList;
        }

        /// <summary> Private method for parsing the &lt;tag-rules&gt; from the XML file.</summary>
        /// <param name="tagAttributeListNode">The top level of &lt;tag-rules&gt;</param>
        /// <param name="parseContext">The <see cref="ParseContext"/> containing the tag rules dictionary to fill.</param>
        private static void ParseTagRules(XmlNode tagAttributeListNode, ParseContext parseContext)
        {
            foreach (XmlElement tagNode in PolicyParserUtil.GetChildrenByTagName(tagAttributeListNode, "tag"))
            {
                string tagName = XmlUtil.GetAttributeValue(tagNode, "name");

                var tag = new Tag(tagName)
                {
                    Action = XmlUtil.GetAttributeValue(tagNode, "action"),
                    AllowedAttributes = GetTagAllowedAttributes(tagNode, tagName, parseContext)
                };

                parseContext.tagRules.Add(tagName.ToLowerInvariant(), tag);
            }
        }

        /// <summary>Get the allowed attributes defined in the provided tag <see cref="XmlElement"/>.</summary>
        /// <param name="tagNode">The node to retrieve the values from.</param>
        /// <param name="tagName">The name of the tag which has attributes defined.</param>
        /// <param name="parseContext">The parse context.</param>
        /// <returns>A dictionary with the allowed attributes.</returns>
        private static Dictionary<string, Attribute> GetTagAllowedAttributes(XmlElement tagNode, string tagName, ParseContext parseContext)
        {
            var allowedAttributes = new Dictionary<string, Attribute>();

            foreach (XmlElement attributeNode in PolicyParserUtil.GetChildrenByTagName(tagNode, "attribute"))
            {
                string attributeName = XmlUtil.GetAttributeValue(attributeNode, "name");
                if (!attributeNode.HasChildNodes)
                {
                    /* All they provided was the name, so they must want a common attribute. */
                    Attribute attribute = parseContext.commonAttributes.GetValueOrTypeDefault(attributeName.ToLowerInvariant());

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
                        AllowedRegExp = GetAllowedRegexpsForRules(attributeNode, tagName, parseContext),
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
        /// <param name="parseContext">The parse context.</param>
        /// <returns>A list with the allowed regular expressions.</returns>
        private static List<string> GetAllowedRegexpsForRules(XmlElement node, string elementName, ParseContext parseContext)
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
                    string pattern = regExName == null ? null : parseContext.commonRegularExpressions.GetValueOrTypeDefault(regExName);
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

        /// <summary> Go through the &lt;css-rules&gt; section of the policy file.</summary>
        /// <param name="cssNodeList">Top level of &lt;css-rules&gt;.</param>
        /// <param name="parseContext">The <see cref="ParseContext"/> containing the CSS rules dictionary to fill.</param>
        private static void ParseCssRules(XmlNode cssNodeList, ParseContext parseContext)
        {
            foreach (XmlElement propertyNode in PolicyParserUtil.GetChildrenByTagName(cssNodeList, "property"))
            {
                string name = XmlUtil.GetAttributeValue(propertyNode, "name");
                string description = XmlUtil.GetAttributeValue(propertyNode, "description");
                string onInvalid = XmlUtil.GetAttributeValue(propertyNode, "onInvalid");

                var property = new Property(name)
                {
                    Description = description,
                    OnInvalid = string.IsNullOrEmpty(onInvalid) ? Constants.DEFAULT_ONINVALID : onInvalid,
                    AllowedRegExp = GetAllowedRegexpsForRules(propertyNode, name, parseContext),
                    AllowedValues = PolicyParserUtil.GetAttributeOrValueFromGrandchildren(propertyNode, "literal-list", "literal", "value"),
                    ShorthandRefs = PolicyParserUtil.GetAttributeOrValueFromGrandchildren(propertyNode, "shorthand-list", "shorthand", "name"),
                };

                parseContext.cssRules.Add(name.ToLowerInvariant(), property);
            }
        }

        /// <summary> Go through the &lt;allowed-empty-tags&gt; section of the policy file.</summary>
        /// <param name="allowedEmptyTagListNode">Top level of &lt;allowed-empty-tags&gt;.</param>
        /// <param name="parseContext">The <see cref="ParseContext"/> containing the allowed empty tags list to fill.</param>
        private static void ParseAllowedEmptyTags(XmlNode allowedEmptyTagListNode, ParseContext parseContext)
        {
            ParseTagListWithLiterals(allowedEmptyTagListNode, parseContext.allowedEmptyTags, Constants.DEFAULT_ALLOWED_EMPTY_TAGS);
        }

        private static void ParseTagListWithLiterals(XmlNode nodeList, List<string> tagListToFill, List<string> defaultTagsList)
        {
            if (nodeList != null)
            {
                foreach (XmlElement element in PolicyParserUtil.GetGrandchildrenByTagNames(nodeList as XmlElement, "literal-list", "literal"))
                {
                    string value = XmlUtil.GetAttributeValue(element, "value");
                    if (!string.IsNullOrEmpty(value))
                    {
                        tagListToFill.Add(value);
                    }
                }
            }
            else
            {
                tagListToFill.AddRange(defaultTagsList);
            }
        }
    }
}
