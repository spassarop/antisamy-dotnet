/*
* Copyright (c) 2009-2020, Jerry Hoff
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
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using HtmlAgilityPack;
using OWASP.AntiSamy.Css;
using OWASP.AntiSamy.Exceptions;
using OWASP.AntiSamy.Html.Model;
using OWASP.AntiSamy.Html.Util;
using Attribute = OWASP.AntiSamy.Html.Model.Attribute;

namespace OWASP.AntiSamy.Html.Scan
{
    /// <summary> This is where the magic lives. All the scanning/filtration logic resides here, but it should not be called
    /// directly. All scanning should be done through a <see cref="AntiSamy"/><c>.Scan()</c> method.</summary>
    public class AntiSamyDOMScanner
    {
        public const string EMPTY_CSS_COMMENT = "/* */";

        // Will hold the results of the scan
        public CleanResults Results { get; set; }
        private void InitBlock() => dom = document.CreateDocumentFragment();
        // Policy holds the parsed attributes from the XML config file
        private readonly Policy policy;
        // All error messages live in here
        private readonly List<string> errorMessages = new List<string>();
        // Needed to parse input
        private readonly XmlDocument document = new XmlDocument();
        // Needed to represent the parsed version of the input
        private XmlDocumentFragment dom;

        public AntiSamyDOMScanner(Policy policy)
        {
            InitBlock();
            this.policy = policy;
        }

        public AntiSamyDOMScanner()
        {
            InitBlock();
            policy = Policy.GetInstance();
        }

        /// <summary> Main parsing engine </summary>
        /// <param name="html">A string whose contents we want to scan.</param>
        /// <returns> A <see cref="CleanResults"/> object with an <see cref="XmlDocumentFragment"/>
        ///  object and its string representation, as well as some scan statistics.</returns>
        /// <exception cref="ScanException">  ScanException </exception>
        // TODO: Use in/out encodings or remove them
        public virtual CleanResults Scan(string html) 
        {
            if (html == null)
            {
                throw new ScanException("No input (null)");
            }

            // Had problems with the &nbsp; getting double encoded, so this converts it to a literal space. This may need to be changed.
            html = html.Replace("&nbsp;", char.Parse("\u00a0").ToString());

            // We have to replace any invalid XML characters
            html = StripNonValidXMLCharacters(html);

            // Holds the maximum input size for the incoming fragment
            int maxInputSize = Policy.DEFAULT_MAX_INPUT_SIZE;

            // Grab the size specified in the config file
            try
            {
                maxInputSize = int.Parse(policy.GetDirective("maxInputSize"));
            }
            catch (FormatException fe)
            {
                Console.WriteLine($"Format Exception: {fe.Message}. Using DEFAULT_MAX_INPUT_SIZE ({Policy.DEFAULT_MAX_INPUT_SIZE}).");
            }

            // Ensure our input is less than the max
            if (maxInputSize < html.Length)
            {
                throw new ScanException($"File size [{html.Length}] is larger than maximum [{maxInputSize}]");
            }

            // Grab start time (to be put in the result set along with end time)
            var start = DateTime.Now;

            // Fixes some weirdness in HTML agility
            if (!HtmlNode.ElementsFlags.ContainsKey("iframe"))
            {
                HtmlNode.ElementsFlags.Add("iframe", HtmlElementFlag.Empty);
            }
            HtmlNode.ElementsFlags.Remove("form");

            // Let's parse the incoming HTML
            HtmlDocument doc = new HtmlDocument();
            doc.LoadHtml(html);

            // Add closing tags
            doc.OptionAutoCloseOnEnd = true;

            // Enforces XML rules, encodes big 5
            doc.OptionOutputAsXml = true;

            // Loop through every node now, and enforce the rules held in the policy object
            for (int i = 0; i < doc.DocumentNode.ChildNodes.Count; i++)
            {
                // Grab current node
                HtmlNode tmp = doc.DocumentNode.ChildNodes[i];

                // This node can hold other nodes, so recursively validate
                RecursiveValidateTag(tmp);

                if (tmp.ParentNode == null) { i--; }
            }

            // All the cleaned HTML
            string finalCleanHTML = doc.DocumentNode.InnerHtml;

            // Grab end time (to be put in the result set along with start time)
            var end = DateTime.Now;
            Results = new CleanResults(start, end, finalCleanHTML, dom, errorMessages);
            return Results;
        }

        private void RecursiveValidateTag(HtmlNode node)
        {
            int maxinputsize = int.Parse(policy.GetDirective("maxInputSize")); // TODO: Should add try/catch or use TryParse
            HtmlNode parentNode = node.ParentNode;
            string tagName = node.Name;

            // TODO: Check this out, might not be robust enough.
            if (tagName.ToLower().Equals("#text"))  // || tagName.ToLower().Equals("#comment"))
            {
                return;
            }

            Tag tag = policy.GetTagByName(tagName.ToLower());
            HtmlNode tmp;
            
            if (tag == null || "filter".Equals(tag.Action))
            {
                var errBuff = new StringBuilder();
                errBuff.Append(string.IsNullOrEmpty(tagName) ? 
                    "An unprocessable " : $"The <b>{HTMLEntityEncoder.HtmlEntityEncode(tagName.ToLower())}</b> ");
                errBuff.Append("tag has been filtered for security reasons. The contents of the tag will remain in place.");

                errorMessages.Add(errBuff.ToString());

                for (int i = 0; i < node.ChildNodes.Count; i++)
                {
                    tmp = node.ChildNodes[i];
                    RecursiveValidateTag(tmp);

                    if (tmp.ParentNode == null) { i--; }
                }
                PromoteChildren(node);
                return;
            }
            else if ("validate".Equals(tag.Action))
            {
                if ("style".Equals(tagName.ToLower()) && policy.GetTagByName("style") != null)
                {
                    var styleScanner = new CssScanner(policy);
                    try
                    {
                        CleanResults cleanStyleSheet = styleScanner.ScanStyleSheet(node.FirstChild.InnerHtml, maxinputsize);
                        errorMessages.AddRange(cleanStyleSheet.GetErrorMessages());

                        /*
                         * If IE gets an empty style tag, i.e. <style/> it will break all CSS on the page. I wish I
                         * was kidding. So, if after validation no CSS properties are left, we would normally be left
                         * with an empty style tag and break all CSS. To prevent that, we have this check.
                         */
                        string cleanHtml = cleanStyleSheet.GetCleanHTML();
                        node.FirstChild.InnerHtml = string.IsNullOrEmpty(cleanHtml) ? node.FirstChild.InnerHtml = EMPTY_CSS_COMMENT : cleanHtml;
                    }
                    //    catch (DomException e)
                    //    {
                    //        addError(ErrorMessageUtil.ERROR_CSS_TAG_MALFORMED, new Object[] { HTMLEntityEncoder.htmlEntityEncode(node.getFirstChild().getNodeValue()) });
                    //        parentNode.removeChild(node);
                    //    }
                    catch (ScanException e)
                    {
                        Console.WriteLine("Scan Exception: " + e.Message);
                        //addError(ErrorMessageUtil.ERROR_CSS_TAG_MALFORMED, new Object[] { HTMLEntityEncoder.htmlEntityEncode(node.getFirstChild().getNodeValue()) });
                        parentNode.RemoveChild(node);
                    }
                }

                for (int currentAttributeIndex = 0; currentAttributeIndex < node.Attributes.Count; currentAttributeIndex++)
                {
                    HtmlAttribute htmlAttribute = node.Attributes[currentAttributeIndex];
                    string name = htmlAttribute.Name;
                    string value = htmlAttribute.Value;
                    Attribute attribute = tag.GetAttributeByName(name);

                    if (attribute == null)
                    {
                        attribute = policy.GetGlobalAttributeByName(name);
                    }

                    bool isAttributeValid = false;

                    if ("style".Equals(name.ToLower()) && attribute != null)
                    {
                        var styleScanner = new CssScanner(policy);

                        try
                        {
                            CleanResults cleanInlineStyle = styleScanner.ScanInlineStyle(value, tagName, maxinputsize);
                            htmlAttribute.Value = cleanInlineStyle.GetCleanHTML();
                            errorMessages.AddRange(cleanInlineStyle.GetErrorMessages());
                        }
                        /*
                        catch (DOMException e)
                        {
                            addError(ErrorMessageUtil.ERROR_CSS_ATTRIBUTE_MALFORMED, new Object[] { tagName, HTMLEntityEncoder.htmlEntityEncode(node.getNodeValue()) });
                            ele.removeAttribute(name);
                            currentAttributeIndex--;
                        }
                        */
                        catch (ScanException ex)
                        {
                            Console.WriteLine(ex.Message);
                            //addError(ErrorMessageUtil.ERROR_CSS_ATTRIBUTE_MALFORMED, new Object[] { tagName, HTMLEntityEncoder.htmlEntityEncode(node.getNodeValue()) });
                            //ele.removeAttribute(name);
                            currentAttributeIndex--;
                        }
                    }
                    else
                    {
                        if (attribute != null)
                        {
                            // TODO: Try to find out how robust this is - do I need to do this in a loop?
                            value = HtmlEntity.DeEntitize(value);

                            foreach (string allowedValue in attribute.AllowedValues)
                            {
                                if (isAttributeValid) { break; }

                                if (allowedValue != null && allowedValue.ToLower().Equals(value.ToLower()))
                                {
                                    isAttributeValid = true;
                                }
                            }

                            foreach (string allowedPattern in attribute.AllowedRegExp)
                            {
                                if (isAttributeValid) { break; }

                                var pattern = "^" + allowedPattern + "$";
                                var match = Regex.Match(value, pattern);
                                if (match.Success)
                                {
                                    isAttributeValid = true;
                                }
                            }

                            if (!isAttributeValid)
                            {
                                var errBuff = new StringBuilder()
                                    .Append($"The <b>{HTMLEntityEncoder.HtmlEntityEncode(tagName)}</b> tag contained an attribute that we couldn't process. ")
                                    .Append($"The <b>{HTMLEntityEncoder.HtmlEntityEncode(name)}</b> attribute had a value of <u>{HTMLEntityEncoder.HtmlEntityEncode(value)}</u>. ")
                                    .Append("This value could not be accepted for security reasons. We have chosen to ");

                                string onInvalidAction = attribute.OnInvalid;
                                if ("removeTag".Equals(onInvalidAction))
                                {
                                    parentNode.RemoveChild(node);
                                    errBuff.Append("remove the <b>" + HTMLEntityEncoder.HtmlEntityEncode(tagName) + "</b> tag and its contents in order to process this input. ");
                                }
                                else if ("filterTag".Equals(onInvalidAction))
                                {
                                    for (int i = 0; i < node.ChildNodes.Count; i++)
                                    {
                                        tmp = node.ChildNodes[i];
                                        RecursiveValidateTag(tmp);
                                        if (tmp.ParentNode == null) { i--; }
                                    }
                                    PromoteChildren(node);
                                    errBuff.Append($"filter the <b>{HTMLEntityEncoder.HtmlEntityEncode(tagName)}</b> tag and leave its contents in place so that we could process this input.");
                                }
                                else
                                {
                                    node.Attributes.Remove(attribute.Name);
                                    currentAttributeIndex--;
                                    errBuff.Append($"remove the <b>{HTMLEntityEncoder.HtmlEntityEncode(name)}</b> attribute from the tag and leave everything else in place so that we could process this input.");
                                }

                                errorMessages.Add(errBuff.ToString());

                                if ("removeTag".Equals(onInvalidAction) || "filterTag".Equals(onInvalidAction))
                                {
                                    return; // Can't process any more if we remove/filter the tag	
                                }
                            }
                        }
                        else
                        {
                            var errBuff = new StringBuilder()
                                .Append($"The <b>{HTMLEntityEncoder.HtmlEntityEncode(name)}")
                                .Append($"</b> attribute of the <b>{HTMLEntityEncoder.HtmlEntityEncode(tagName)}</b> tag has been removed for security reasons. ")
                                .Append("This removal should not affect the display of the HTML submitted.");

                            errorMessages.Add(errBuff.ToString());
                            node.Attributes.Remove(name);
                            currentAttributeIndex--;
                        } // End if attribute is or is not found in policy file
                    } // End if style.equals("name") 
                } // End while loop through attributes 

                for (int i = 0; i < node.ChildNodes.Count; i++)
                {
                    tmp = node.ChildNodes[i];
                    RecursiveValidateTag(tmp);
                    if (tmp.ParentNode == null) { i--; }
                }
            }
            else if ("truncate".Equals(tag.Action))
            {
                Console.WriteLine("truncate");
                HtmlAttributeCollection attributes = node.Attributes;

                while (attributes.Count > 0)
                {
                    var errBuff = new StringBuilder()
                        .Append($"The <b>{HTMLEntityEncoder.HtmlEntityEncode(attributes[0].Name)}")
                        .Append($"</b> attribute of the <b>{HTMLEntityEncoder.HtmlEntityEncode(tagName)}</b> tag has been removed for security reasons. ")
                        .Append("This removal should not affect the display of the HTML submitted.");

                    node.Attributes.Remove(attributes[0].Name);
                    errorMessages.Add(errBuff.ToString());
                }

                HtmlNodeCollection childNodes = node.ChildNodes;
                int i = 0, j = 0, length = childNodes.Count;

                while (i < length)
                {
                    HtmlNode nodeToRemove = childNodes[j];
                    if (nodeToRemove.NodeType != HtmlNodeType.Text && nodeToRemove.NodeType != HtmlNodeType.Comment)
                    {
                        node.RemoveChild(nodeToRemove);
                    }
                    else
                    {
                        j++;
                    }
                    i++;
                }
            }
            else
            {
                parentNode.RemoveChild(node);
                errorMessages.Add($"The <b>{HTMLEntityEncoder.HtmlEntityEncode(tagName)}</b> tag has been removed for security reasons.");
            }
        }

        // TODO: Use in future refactor or delete, its purpose is to build errors from constants and parameters.
        private void AddError(string errorKey, object[] objs)
        {
            errorMessages.Add(errorKey);
            //errorMessages.add(ErrorMessageUtil.getMessage(errorKey, objs));
        }

        private void PromoteChildren(HtmlNode node)
        {
            HtmlNodeCollection nodeList = node.ChildNodes;
            HtmlNode parent = node.ParentNode;

            while (nodeList.Count > 0)
            {
                HtmlNode removeNode = node.RemoveChild(nodeList[0]);
                parent.InsertBefore(removeNode, node);
            }

            parent.RemoveChild(node);
        }
        
        private string StripNonValidXMLCharacters(string textToClean)
        {
            if (string.IsNullOrEmpty(textToClean))
            {
                return string.Empty; // Vacancy test.
            }

            var cleanText = new StringBuilder(); // Used to hold the output.
            char current; // Used to reference the current character.

            for (int i = 0; i < textToClean.Length; i++)
            {
                current = textToClean[i]; // NOTE: No IndexOutOfBoundsException caught here; it should not happen.
                if ((current == 0x9) 
                    || (current == 0xA) 
                    || (current == 0xD) 
                    || ((current >= 0x20) && (current <= 0xD7FF)) 
                    || ((current >= 0xE000) && (current <= 0xFFFD)) 
                    || ((current >= 0x10000) && (current <= 0x10FFFF)))
                {
                    cleanText.Append(current);
                }
            }

            return cleanText.ToString();
        }
    }
}