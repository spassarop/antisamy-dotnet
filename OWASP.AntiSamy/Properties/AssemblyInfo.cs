using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// General Information about an assembly is controlled through the following 
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
[assembly: AssemblyTitle("AntiSamy")]
[assembly: AssemblyDescription("A library for performing fast, configurable cleansing of HTML coming from untrusted sources. Refactored from an old project in .NET framework 2.0 to the current version in .NET core 3.1.\r\n\r\nAnother way of saying that could be: It's an API that helps you make sure that clients don't supply malicious cargo code in the HTML they supply for their profile, comments, etc., that get persisted on the server. The term \"malicious code\" in regard to web applications usually mean \"JavaScript.\" Mostly, Cascading Stylesheets are only considered malicious when they invoke JavaScript. However, there are many situations where \"normal\" HTML and CSS can be used in a malicious manner.")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("spassaro")]
[assembly: AssemblyProduct("AntiSamy")]
[assembly: AssemblyCopyright("Copyright © 2020 - Arshan Dabirsiaghi, Sebastián Passaro")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

// Setting ComVisible to false makes the types in this assembly not visible 
// to COM components.  If you need to access a type in this assembly from 
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]

// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("1512584d-4e5a-4ed6-9088-e8139182066c")]

// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version 
//      Build Number
//      Revision
//
// You can specify all the values or you can default the Build and Revision Numbers 
// by using the '*' as shown below:
// [assembly: AssemblyVersion("1.0.*")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: InternalsVisibleTo("OWASP.AntiSamyTests")]
[assembly: NeutralResourcesLanguage("en-US")]
