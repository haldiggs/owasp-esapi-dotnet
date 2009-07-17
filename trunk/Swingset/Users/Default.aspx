<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="Owasp.Esapi.Swingset.Users.Default" MasterPageFile="~/Esapi.Master" %>
<asp:Content ID="DefaultContent" ContentPlaceHolderID="SwingsetContentPlaceHolder" runat="server">
    <ul>
    <li><asp:HyperLink ID="hlAccessController" runat="server"  NavigateUrl="~/Users/Examples/AccessControllerPage.aspx">Access Controller</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlAccessReferenceMap" runat="server"  NavigateUrl="~/Users/Examples/AccessReferenceMapPage.aspx">Access Reference Map</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlEncoder" runat="server"  NavigateUrl="~/Users/Examples/EncoderPage.aspx">Encoder</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlEncryptor" runat="server"  NavigateUrl="~/Users/Examples/EncryptorPage.aspx">Encryptor</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlHttpUtilities" runat="server"  NavigateUrl="~/Users/Examples/HttpUtilitiesPage.aspx">HTTP Utilities</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlIntrusionDetector" runat="server"  NavigateUrl="~/Users/Examples/IntrusionDetectorPage.aspx">Intrusion Detector</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlRandomizer" runat="server"  NavigateUrl="~/Users/Examples/RandomizerPage.aspx">Randomizer</asp:HyperLink></li>
    <li><asp:HyperLink ID="hlValidator" runat="server"  NavigateUrl="~/Users/Examples/ValidatorPage.aspx">Validator</asp:HyperLink></li>
    </ul>
    <ul>
    <li><asp:HyperLink ID="hlChangePassword" runat="server"  NavigateUrl="~/Users/ChangePassword.aspx">Change Password</asp:HyperLink></li>
    <li><asp:LoginStatus ID="EsapiLoginStatus" runat="server"  OnLoggingOut="EsapiLoginStatus_LoggingOut" /></li>
    </ul>
</asp:Content>
